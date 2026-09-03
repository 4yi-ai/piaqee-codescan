# 4YI Marketplace 项目部署指南

本文用于把一个新的 GitHub 项目接入 4YI 应用市场，并尽量避免 PentAGI
接入过程中遇到的服务识别错误、数据丢失、模型不可选、冷启动失败和重复发布等问题。

> 适用范围：Dedicated app（每个组织独立安装）的仓库式应用。
> 平台规则可能继续演进，上架前仍应以 xclaw 当前的
> `src/lib/marketplace-import/app-declaration.ts` 为最终准则。

## 一、最重要的原则

1. **仓库根目录必须提供 `4yi-app.json`。** 不要依赖 Run Analyze 猜测
   Docker Compose。声明文件存在且合法时，分析器会按声明生成服务拓扑；否则多服务项目
   很容易被误判成 `single_service`。
2. **只能有一个公开服务。** 恰好一个服务设置 `route: "public"`，数据库、Redis、
   worker、executor 等全部使用 `route: "internal"`。
3. **所有运行期数据都必须放到持久卷。** 数据库有 PVC 不代表应用文件也安全。
   上传文件、生成结果、缓存或本地 SQLite 如果仍写在容器层，Pod 重建、升级或恢复后都会丢失。
4. **应用不能依赖宿主机能力。** 不允许假设存在 Docker socket、`hostPath`、host network
   或 privileged 容器。需要执行工具时，应拆成一个内部 executor/worker 服务。
5. **模型使用平台的逻辑模型名。** `models[].default` 和 `allowed` 填模型目录中的公开
   `name`，不要填供应商路由 ID、Bedrock ARN 或历史别名。
6. **先验证 Proposal，再 Apply。** Run Analyze 只生成新草稿；Apply 才把草稿写成 App Spec。
   Release 构建指定 commit；Publish 才把 release 切换为市场当前版本。

## 二、上架前先判断项目是否适合 4YI

在改代码前确认以下问题：

- Web 服务是否监听 `0.0.0.0`，而不是只监听 `127.0.0.1`。
- 容器内是否使用纯 HTTP；TLS 应由 4YI 入口终止。
- 是否有不依赖登录、数据库重迁移或外部模型调用的快速健康检查接口。
- 是否会在请求过程中启动 Docker 容器、浏览器或其他子容器。
- 是否有数据库、Redis、队列、上传文件、生成文件或本地缓存。
- 是否依赖 WebSocket、SSE、长轮询或超过网关超时的同步任务。
- 前端环境变量是在构建期读取，还是可以在运行期注入。
- 首次启动是否执行耗时 migration、模型探测、镜像下载或数据初始化。

如果项目依赖 Docker socket，应先完成 executor/worker 化，再做市场上架。不要通过提升
Pod 权限绕过平台限制。

## 三、仓库必须准备的内容

### 3.1 根目录 `4yi-app.json`

下面是一个通用多服务模板。删除不需要的服务，不要原样保留占位值。

```json
{
  "version": 1,
  "services": [
    {
      "name": "web",
      "type": "web",
      "imageSource": "build",
      "dockerfile": "Dockerfile",
      "context": ".",
      "route": "public",
      "port": 8080,
      "healthPath": "/healthz",
      "env": {
        "HOST": "0.0.0.0",
        "PORT": "8080",
        "DATA_DIR": "/app/data"
      },
      "storage": {
        "sizeGb": 10,
        "mountPath": "/app/data",
        "fsGroup": 10001
      },
      "resources": {
        "cpu": 1,
        "memoryMb": 2048
      }
    },
    {
      "name": "postgres",
      "type": "postgres",
      "imageSource": "registry",
      "image": "pgvector/pgvector:pg16",
      "route": "internal",
      "port": 5432,
      "storage": {
        "sizeGb": 10,
        "mountPath": "/var/lib/postgresql/data",
        "subPath": "pgdata"
      },
      "resources": {
        "cpu": 0.5,
        "memoryMb": 1024
      }
    },
    {
      "name": "worker",
      "type": "worker",
      "imageSource": "build",
      "dockerfile": "Dockerfile",
      "context": "worker",
      "route": "internal",
      "port": 8022,
      "healthPath": "/healthz",
      "resources": {
        "cpu": 1,
        "memoryMb": 2048
      }
    }
  ],
  "models": [
    {
      "env": "LLM_MODEL",
      "type": "chat",
      "default": "claude-sonnet-4-6",
      "allowed": [
        "claude-sonnet-4-6",
        "deepseek.v3.2",
        "qwen3.7-max"
      ]
    }
  ]
}
```

### 3.2 当前声明格式的硬性要求

- `version` 只能是 `1`。
- `services` 不能为空，服务名只能使用小写字母、数字和中划线，最长 63 个字符。
- 服务类型为 `web | api | worker | postgres | redis`。
- 必须恰好有一个 `route: "public"`。
- 公开服务必须配置以 `/` 开头的 `healthPath`。
- 端口必须为 `1-65535` 的整数。
- `env` 的值必须全部是字符串；不要写 JSON 数字或布尔值。
- `imageSource: "build"` 必须提供 `dockerfile`，可以提供 `context`，不能提供 `image`。
- `imageSource: "registry"` 必须提供带 tag 或 digest 的 `image`，不能同时提供
  `dockerfile/context`。
- `storage.mountPath` 必须是容器绝对路径；`subPath` 必须是安全的相对路径。
- `fsGroup` 用于解决非 root 容器写 PVC 的权限问题，应与镜像运行用户的组权限匹配。
- `models[].allowed` 如果存在，必须是非空数组并包含 `default`。
- 当前资源上限为 CPU 32、内存 262144 MiB、单卷 16384 GiB；实际套餐可能更低。

### 3.3 Dockerfile 与 build context

平台按 `context + dockerfile` 定位文件，并从 context 发送构建内容。例如：

```json
{
  "context": "backend",
  "dockerfile": "Dockerfile"
}
```

对应仓库文件是 `backend/Dockerfile`，不是 `backend/backend/Dockerfile`。Dockerfile 的
`COPY` 也只能访问 context 内的内容。

每个 build 服务在提交前都应独立构建：

```bash
docker build -f Dockerfile .
docker build -f backend/Dockerfile backend
```

Registry 服务应尽量固定版本或 digest。`latest` 会让相同 release 在不同时间得到不同镜像，
不利于回滚和排障。

## 四、服务通信与环境变量

### 4.1 内部 DNS

多服务部署的 Kubernetes Service 通常按应用名和服务名组合生成，例如：

```text
<app-slug>-postgres
<app-slug>-worker
```

不要直接照搬 Docker Compose 中的 `postgres` 或 `worker` 主机名。Run Analyze 后必须在
Deployment Proposal 中核对最终 DNS，再确认 `DATABASE_URL`、`REDIS_URL`、`WORKER_URL`
等变量指向正确地址。

内部服务不应设置公开路由，也不应通过公网域名互相调用。

### 4.2 Secrets

`4yi-app.json.env` 只放非敏感配置。以下内容必须在 Import 的 **Secrets** 步骤配置：

- 数据库密码或完整的敏感 `DATABASE_URL`
- LLM gateway key
- Cookie/JWT signing secret
- OAuth client secret
- executor token
- 第三方 API key

Secret 名必须与应用实际读取的环境变量完全一致。不要把真实密码提交到仓库，也不要用
开发环境固定密码发布到市场。

### 4.3 前端变量

Vite/Next.js 等框架常在构建阶段把公开变量写进静态文件。运行期注入环境变量不会自动修改
已经生成的 JS。需要动态 hostname/API URL 时，优先使用相对路径或运行期配置接口；否则在
Release 构建前明确提供 build-time env。

## 五、持久化设计

这是最容易遗漏、也最容易造成用户数据损失的一项。

### 5.1 不只检查数据库

逐项搜索应用的写入路径：

- 数据库数据目录
- 上传附件和资源 blob
- 用户生成的报告、图片和导出文件
- 本地 SQLite
- 会话、任务状态或 flow cache
- 用户可见且期望重启后仍存在的工作目录

数据库行还在但 blob 文件不在，会出现“历史记录可见、打开或发送附件时报
`no such file or directory`”的假完整状态。数据库和对应文件目录必须同时持久化。

### 5.2 数据库卷

Postgres 新 PVC 根目录可能包含平台文件，建议使用 `subPath` 或配置 `PGDATA` 子目录：

```json
"storage": {
  "sizeGb": 10,
  "mountPath": "/var/lib/postgresql/data",
  "subPath": "pgdata"
}
```

### 5.3 应用卷

如果应用通过 `DATA_DIR=/app/data` 写文件，storage 的 `mountPath` 必须与之完全一致。
只挂载父目录或另一个路径不会自动生效。

上线前至少验证一次：上传文件或创建任务 → 暂停/恢复或重新部署 → 数据仍能读取。

## 六、健康检查、启动和网关超时

健康接口应满足：

- 无需登录。
- 不调用 LLM 或慢速第三方 API。
- 不执行 migration。
- 正常时快速返回 HTTP 200。
- 能反映服务进程已经可以接收请求。

应用应监听 `0.0.0.0:<port>`，并关闭容器内 TLS。数据库和内部服务启动顺序不可完全依赖
Compose 的 `depends_on`，应用必须对 DNS、数据库和 worker 冷启动实现退避重试。

不要把模型探测、浏览器启动、镜像下载或长任务放在首次 HTTP 请求内同步等待。它们可能超过
ALB/API 网关超时并表现为 502。更稳妥的方式是：

1. 请求先创建任务并立即返回。
2. 后台 worker 执行耗时工作。
3. 前端通过轮询、SSE 或 WebSocket 查看状态。
4. 冷启动页面允许重试，不能一次失败就跳回登录页。

## 七、模型接入

### 7.1 声明模型槽位

需要用户在安装时选择模型的应用，必须在 `4yi-app.json.models` 声明槽位。否则安装弹窗只会
显示价格确认，不会出现模型下拉框。

安装时最终显示的模型是以下集合的交集：

```text
应用 allowed 白名单
∩ 当前套餐允许的模型
∩ 平台模型目录中已启用的模型
```

所以白名单里有模型但安装时不显示，优先检查套餐和平台模型目录，不要立即改应用代码。

### 7.2 模型 ID 与运行配置

- `default` 必须包含在 `allowed` 中。
- 使用模型目录的逻辑名称，例如 `claude-sonnet-4-6`，不要使用旧供应商裸 ID。
- 如果模型目录存在多个供应商路由，`allowed` 仍只填写逻辑名称；实际请求使用模型目录中
  标记为“主用”的提供商。例如 GPT 5.6 Luna/Sol/Terra 使用 `gpt-5.6-luna`、
  `gpt-5.6-sol`、`gpt-5.6-terra`，由目录的 Custom 主用路由转发，不能在声明中填写
  `openai.gpt-5.6-*` 或 AWS Bedrock 上游 ID。
- 确认安装选择最终写入 `models[].env` 指定的变量。
- 应用 UI 应显示实际配置模型，而不是写死为 `openai` 或 `custom`。
- 不同供应商的参数支持不同。例如部分 Claude 路由不能同时接受 `temperature` 和
  `top_p`，调用层应按供应商能力生成参数。
- 图片输入只有在应用真正发送多模态内容、且所选模型支持视觉时才有效；上传文件到资源库
  本身不等于模型已经读取文件。

## 八、正确的导入和发布流程

### 8.1 第一次导入

1. 为市场适配建立独立分支，例如 `4yi-marketplace`。
2. 提交 `4yi-app.json`、所有 Dockerfile、健康接口和必要代码。
3. 在 AI Marketplace Import 中选择 GitHub 仓库、分支和 **Dedicated app**。
4. 点击 **Create** 创建导入任务。不要连续重复点击；每次 Create 都会产生一条 Import
   History 记录。
5. 点击 **Run Analyze**。
6. 在 AI Analysis 确认：`blockers = 0`，部署模型与声明一致；多服务项目应为
   `multi_service`。
7. 在 Deployment Proposal 逐项核对服务、路由、端口、health、storage、resources、env
   和内部 DNS。
8. 配置 Secrets 和 Pricing。
9. 点击 **Apply** 写入 App Spec。
10. 创建 **Release**，确认它构建的是目标 commit。
11. 完成 Publish Gate（smoke、billing dry-run、tenant isolation）。
12. 点击 **Publish**。
13. 使用测试组织完成真实安装和业务验收。

### 8.2 更新已经发布的应用

推荐继续使用同一个仓库、分支和导入记录：

1. 推送新 commit。
2. Run Analyze，核对 Proposal。
3. Apply。
4. 新建 Release。
5. 通过 Publish Gate 后 Publish。

Publish 更新的是市场当前 release，新安装会使用新版本；已经存在的租户实例是否升级，应通过
平台的 Upgrade/重新安装流程明确执行，不能假设 Publish 会自动替换所有运行实例。

不要为了更新而删除旧 published 记录，也不要反复 Create 同一仓库，否则 Import History 会
出现多条相似任务，容易在错误的 job/spec/release 上操作。

### 8.3 四个按钮的含义

| 操作 | 作用 | 主要风险 |
| --- | --- | --- |
| Run Analyze | 读取当前分支并重新生成 Proposal 草稿 | 没有合法声明时可能猜错服务 |
| Apply | 将当前 Proposal 写为 App Spec | 错误 Proposal 会成为后续 release 的部署结构 |
| Release | 构建并固化某个 commit | 分支未推送、context 错误会导致构建失败 |
| Publish | 将 release 设为市场当前版本 | 新安装开始使用该版本，但不等于所有旧实例已升级 |

## 九、每次 Apply 前的人工核对

- [ ] `4yi-app.json` 位于仓库根目录且是合法 JSON。
- [ ] 服务数量与预期一致。
- [ ] 恰好一个 public 服务。
- [ ] 数据库、Redis、worker/executor 均为 internal。
- [ ] 每个 build 服务的 Dockerfile 和 context 可以本地构建。
- [ ] Registry 镜像带明确 tag/digest。
- [ ] public port 与进程监听端口一致。
- [ ] healthPath 无认证、快速返回 200。
- [ ] 内部 URL 使用 Proposal 中的真实服务 DNS。
- [ ] 所有运行期写目录都有持久卷。
- [ ] PVC 权限与容器 UID/GID 匹配。
- [ ] Secrets 没有写入代码或声明文件。
- [ ] 模型默认值在 allowed 中，且模型名存在于平台目录。
- [ ] 套餐模型与应用白名单有非空交集。
- [ ] 资源配置足够完成启动和首个任务。
- [ ] 首次请求不会同步执行超时任务。
- [ ] Proposal blockers 为 0。
- [ ] Release commit SHA 是刚推送的目标 commit。
- [ ] 测试安装完成了暂停/恢复、重新部署和数据持久化验证。

## 十、PentAGI 适配中的问题与通用结论

| 现象 | 根因 | 下一个项目的预防方式 |
| --- | --- | --- |
| Analyze 生成 `single_service` | 依赖扫描器猜 Compose | 根目录提交完整 `4yi-app.json` |
| 数据库和 executor 消失 | Proposal 只识别 web | 在声明中列出全部内部服务 |
| 数据库正常但上传附件丢失 | 只给 Postgres 挂卷，web 文件在容器层 | 盘点并挂载应用自身的数据目录 |
| Postgres 新卷初始化失败 | PVC 根目录/权限与 PGDATA 冲突 | 使用 `subPath`/PGDATA 子目录并核对 fsGroup |
| Kali 工具不能运行 | 平台不提供宿主 Docker socket | 拆分常驻内部 executor 服务 |
| 安装时没有模型选择 | 未声明模型槽位或交集为空 | 配置 `models`，核对套餐和目录 |
| 选择 Claude，应用却显示 OpenAI/custom | UI 展示供应商占位名或 env 未透传 | 展示实际模型 env，并验证安装后的容器配置 |
| 首次创建任务返回 502 | 同步模型探测或初始化超过网关超时 | 异步创建任务，冷启动重试 |
| 模型请求 502/400 | 向模型发送不兼容参数 | 按供应商能力过滤参数 |
| 暂停恢复后前端模块加载失败 | 浏览器缓存引用旧 hash 静态资源 | 升级后刷新/自动重载 chunk，避免长期缓存 HTML |
| 历史 flow 偶发打不开 | 一次加载过多日志，接口超时 | 分页、拆分查询、必要索引和失败隔离 |
| Import History 出现多条相同记录 | 重复点击 Create | 更新时复用现有导入任务 |

## 十一、建议保留的回滚材料

每次重大调整前保存：

- 当前已 Apply 且验证可用的 manifest/Proposal JSON。
- 当前 App Spec ID、Release ID 和 commit SHA。
- Secrets 名称清单（不要保存 secret value）。
- 数据库 migration 版本。
- 测试安装的组织、hostname 和验收结果。

如果新 Analyze 结果异常，先停止 Apply，拿备份逐项对比；不要在正在服务用户的应用上边猜边
发布。首次适配新项目时，始终先使用测试组织完成安装、暂停/恢复、升级和卸载验证，再开放给
真实用户。

# kgateway 统一网关实施计划

`kgateway` 和 `kstack` 保持独立仓库、构建单元和进程，共用一套部署配置和版本兼容矩阵。`kgateway` 是 Kense OS 的公共入口与策略执行点，`kstack` 是首个接入的 MaaS 执行面。首个上线里程碑覆盖 MaaS 和一个独立的只读 REST 服务。LLM、通用 API、MCP、A2A 全部通过同一套准入与审计验收后，完成统一网关交付。 [统一网关设计](../os/README.zh-CN.md) · [请求流程](../os/docs/design/platform-flow-blueprint.html)

## 仓库和服务分工

| 交付单元 | 职责 |
| --- | --- |
| `kgateway` | 公共 TLS 入口、Key 本地校验、URN 解析、scope 与预算准入、短时服务凭据、目标选择和版本流量权重。负责协议转发、背压、排空、入口计量与审计证据投递。 |
| `kstack` | 模型目录、部署版本、健康和就绪事实。私有 MaaS 入口校验服务凭据并在指定部署内选择实例，复用唤醒、serving network、agent 隧道和推理转发。负责模型 token 的权威计量。 |
| 平台控制面 | Identity 持有 Key 权威和信任根，Registry 持有能力目录，Releases 持有版本与流量意图，Metering 持有额度与用量账本，Audit 持有租户审计链，Vault 持有第三方凭据。当期以这些契约为边界交付最小可部署控制面。 |
| 共享契约与联合部署 | 首版在 `kgateway/contracts/` 维护语言中立的 schema、OpenAPI 和兼容样本。生成 Rust 和 Go 客户端并锁定契约版本，两仓可独立构建。联合配置随 `kgateway/deploy/kstack/` 交付，按镜像摘要和契约版本锁定可配对发行物。 |

首期控制面以 `kgateway/control-plane/` 独立构建并运行，同一个进程提供快照发布、Key 与吊销、预算租约、事件接收和审计回执，以持久化状态支撑真实联调。保持平台契约可由 Kense 控制面接管。联合部署将控制面、网关 Node API、`kstack` 管理面与节点通道放在各自的管理或私有网络上，对租户公开 `kgateway`。 [OS 控制面与数据面](../os/docs/design/unified-ai-platform-architecture.html) · [现有 Node API](src/node_api.rs)

## 请求与故障语义

1. **匹配和认证。** 从本地快照匹配已注册的入口，校验 Key 哈希、代际、有效期与 `tenant/project/env`。清除客户端身份保留头和主 Key，按协议在有界解析后验证方法和实际资源。通用准入覆盖托管路由的快速路径、普通转发和协议分流。未知操作或越权请求在联系业务上游前拒绝。 [现有入口](src/entrypoint.rs) · [推理本地鉴权](src/inference/authorization.rs)
2. **预扣和换证。** 在当前租户、服务和操作对应的本地额度中预扣，生成 `request_id` 和 `reservation_id`。身份服务预置可轮换的受限签发授权。网关本地签发 5–15 分钟、单服务 `aud` 的 JWT，携带实际 URN、最小 scope 和关联 ID，通过 mTLS 交付。网关以验证后的 claims 回注 `subject/plane/org`。下游以经过验证的凭据建立用户上下文。服务间委托逐跳降权，沙箱侧通过执行端代理调用。 [OS 信任传播](../os/README.zh-CN.md)
3. **选路和回退。** 用同一个已激活的运行时执行授权、解析不可变部署版本并选择目标。`kstack` 把凭据绑定的部署 ID 和版本用于路由约束，再在该部署内重试实例。`kgateway` 只在响应开始前且请求可安全重试时跨目标回退。写操作需要端到端的幂等键或上游尚未执行的明确信号。已接收的流保持原目标并在期限内排空。 [现有推理分发](src/entrypoint/inference_dispatch.rs) · [kstack 推理入口](../kstack/internal/server/proxy/proxy.go)
4. **结算和审计。** `kgateway` 为入口请求记录请求数和出网字节，`kstack` 从可信上游结果记录模型 token。两者以稳定的 `event_id` 处理重投，按 `trace_id`、`billing_parent` 和 `reservation_id` 关联，单个计量维度只由其权威生产者出账。为成功、失败、断连和取消保留终态。用量未知时保留预扣并进入对账。长任务由执行服务按预扣、心跳、结算报告。敏感操作先取得跨故障域可恢复的审计回执，普通审计异步落盘补投。Vault 发布 `secret_ref` 和版本给指定执行端。 [用量队列实现](src/usage/spool.rs) · [OS 计量和审计](../os/docs/design/unified-ai-platform-architecture.html)

| 故障 | 数据面行为 |
| --- | --- |
| 控制面断连或快照被拒绝 | 在快照、签发授权、吊销新鲜度和额度租约有效的条件下，使用上一份已验证快照。任何准入条件失效时拒绝新请求。恢复后报告精确 revision、摘要和本地就绪状态。 |
| Key 吊销 | 独立于快照的高优先级通道传输 Key ID 与代际，网关持久化位点和失效状态，清理验证缓存。断连恢复从位点续投，路由回滚仍应用最新吊销状态。达到吊销窗口上限时拒绝新准入。 |
| 预算服务或副本故障 | 使用绑定副本和租约代际的独占额度。持久化预扣或采用等价的保守扣留，重启、更新和副本替换均以剩余额度恢复。未清算额度在对账前继续占用全局硬顶。 |
| 事件接收端不可用或磁盘满 | 使用有界持久队列补投。准入前确认可记录起始和终态事件，容量不足时拒绝对应请求。敏感动作缺失审计回执时拒绝执行。 |
| 目标故障或版本撤回 | 健康检查只摘除快照内目标。恢复上一版目标和权重时发布更高 revision，保留当前权限、吊销、用量和额度状态。 |

## 合并顺序与验收

| 批次 | 改动 | 合并门槛 |
| --- | --- | --- |
| 1 基线与契约 | 锁定两仓基线，记录当前 OpenAI SDK、JSON/SSE 的行为和吞吐、P99、首 token 延迟。列出公开路由、品牌入口、状态格式和跨仓协议消费者。提交 schema、兼容样本和配对版本清单。 | Rust 和 Go 使用同一批契约样本，注册表与路由清单可做一致性检查。旧发行物、状态和重放样本可复现。 |
| 2 改名与文档迁移 | 以 `kgateway` 统一 Cargo 包、lib、二进制和产品标识。收敛发布版本来源，迁移旧文档上的构建和证据检查。提交旧状态转换及升级演练。 | CLI、安装器、镜像、Helm 和发布归档可在新名称下验证。旧状态恢复、在途用量和精确 ACK 的迁移测试通过。 |
| 3 本地策略和 MaaS | 在 `kgateway` 的 `src/gateway/`、`src/managed_snapshot.rs` 和 `src/entrypoint.rs` 接入统一准入与版本化快照。在 `kstack/internal/server/app/` 装配私有 MaaS 入口，在 `internal/server/proxy/` 绑定受验证的部署范围并加入持久用量投递。启动两仓真实进程和控制面，用测试引擎完成联合 CI。 | 同一把 Key 调通 `/v1/models`、`/v1/chat/completions` 的 JSON 与 SSE 以及独立只读 REST API。验证换证、跨租户拒绝、错误 `aud` 和未注册路由拒绝。由上游断言主 Key 未到达。 [kstack 路由分流](../kstack/internal/server/app/dataplane.go) |
| 4 故障验证与切流 | 运行双网关副本、`kstack` 和持久控制面。按租户灰度，从测试引擎验证推进到真实模型。将现有 embeddings、completions、files、batches 等从实际路由清单逐项纳入。 | 完成下方上线验收后接真实流量。现有租户使用签发的 Kense Key 逐批迁移。切换完成后关闭对应的 `kstack` 旧公共入口。 |
| 5 MCP 和 A2A | MCP 先交付发现、工具级 URN 授权、会话归属、取消和排空。A2A 交付代理发现、委托降权、任务状态与恢复、取消。发布统一公开路由和兼容客户端。 | 真实客户端和上游通过重连、取消、权限变更和恢复测试。四类协议能在同一套 Key、目录、计量和审计契约下运行。 |

## 当前实现

- 已交付独立的 Rust 网关、Go MaaS 私有入口和 SQLite 控制面。联合测试使用两台网关和 kstack 测试引擎，从同一把主 Key 调用目录、模型列表、JSON 聊天和 SSE 聊天。网关入口用量与 kstack token 用量按请求和预扣 ID 对账。
- 已在本地启动三容器部署包。控制面通过 mTLS 发布快照，网关用服务凭据访问 kstack。网关与服务端用量分别重投，控制面返回精确回执。旧文档已移除，版本和证据索引集中在发布清单。 [联合部署](deploy/kstack/README.md) · [发布清单](release.json)
- 控制面在当前预算窗口结束前预发下一窗口的租约，每台网关从租约生效时刻开始使用独占额度。联合测试在两台副本耗尽原额度后关闭控制面，跨窗口各放行两次请求，随后验证超额拒绝和用量补投。旧版数据库中的未到期租约保持原有 ID 和额度。 [跨窗口联合测试](tests/platform_control_plane_e2e.py)
- 额度支持租户、项目和环境三层硬上限。一次请求在同一份持久账本中原子预扣所有适用租约。双副本测试验证同环境的两把 Key 共享额度、项目和租户分别触发限额、重启后保留已用额度，以及敏感操作拒绝缺失或错绑的租约。 [额度联合测试](tests/platform_control_plane_e2e.py) · [租约契约](contracts/platform-policy-v1.schema.json)
- Files 和 Batches 复用 kstack 的存储和执行器。同租户的不同 Key 以及跨租户 Key 均无法读取对方资源。批任务保存获准的部署版本，按输入行上限预留预算，逐条推理用量关联到提交时的预留。联合进程测试覆盖上传、读取、分页、删除、批任务输出、越权提交和预算耗尽。 [联合进程测试](tests/platform_control_plane_e2e.py)
- MCP 支持工具级准入、按 Key 授权过滤工具发现、签名绑定会话、SSE 恢复和终止。A2A 支持注册的 JSON-RPC 方法，任务操作检查代理签发的身份绑定票据。委托票据绑定目标操作和原 Key，逐跳缩小范围并保存授权链，跨副本只可用一次。 [MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) · [A2A 委托契约](contracts/a2a-delegation-v1.schema.json)
- 控制面为身份变更、网关请求终态和 MaaS 用量追加租户审计链。审计员使用独立凭据，审计查询本身产生回执。敏感路由取得与请求绑定的控制面回执后执行。
- Vault 已通过本地联合测试，覆盖密文封存、绑定激活、轮换、撤销和执行服务按提交记录取回密文。签发凭据只包含引用与版本。联合 CI 接受固定 kstack 提交并记录两仓提交与契约摘要。 [Vault 联合测试](tests/platform_vault_e2e.py) · [配对工作流](.github/workflows/paired-maas.yml)
- `--openbao` 配对联测启动固定镜像的独立 OpenBao Transit 和独立解密工作负载。测试验证加密与解密权限分离、作用域派生上下文、KMS 封存时拒绝、解封恢复、凭据与 KMS 密钥轮换，以及退役版本拒绝解密。联测扫描网关和控制面日志、数据库及审计事件，验证受保护的明文和令牌未进入这些位置。配对 CI 记录 OpenBao 镜像摘要。 [KMS 接入与验收](deploy/kstack/README.md#openbao-transit-integration) · [兑换密文契约](contracts/vault-envelope-v1.schema.json)
- 审计见证支持独立数据库、独立签名、定期链头锚定和审计员恢复接口。开启见证后，敏感请求在见证签名验证通过后放行。 [部署配置](deploy/kstack/README.md)
- 控制面支持加密检查点交接。交接封存旧库，独立见证签发归档、策略和审计链头摘要，并只向一个恢复目标确认同一检查点。双副本演练从新路径恢复吊销、额度、发布和已结算用量，补投停机期间留在网关的事件，并拒绝落后于见证的备份。 [交接与恢复](deploy/kstack/README.md#handoff-and-restore-the-control-plane) · [双副本故障演练](tests/platform_recovery_e2e.py)
- kstack 批任务持久化状态与心跳报告，控制面对账已占用和未使用的预留请求单位。网关的硬额度保留到当前预算窗口结束。 [批任务报告契约](contracts/maas-batch-report-v1.schema.json)
- 本地联测覆盖 OpenAI Python SDK、MCP 2025-11-25 的 Python SDK，以及 A2A JSON-RPC 的 Python SDK。 [MCP 与 A2A SDK 测试](tests/platform_protocol_sdk.py) · [OpenAI SDK 测试](tests/openai_sdk/test_conformance.py)
- URN 注册表生成精确方法与路径的 ACL、OpenAPI 3.1 以及 Rust 和 Go 请求客户端。配对测试编译生成代码并通过网关调用模型列表、文件详情和 SSE，同时校验 MCP、A2A 和 REST 的注册路由。控制面与离线导出共用注册表，配对产物记录契约与客户端摘要。 [生成器](control-plane/registry.py) · [OpenAPI 样本](contracts/openapi.json) · [SDK 联测](tests/platform_registry_sdk.py)
- 本地配对性能基线用同一 kstack 模拟引擎对比直连与经过 kgateway 的 JSON/SSE。灰度改造完成后的复测共完成 512 次请求，所有流正常结束。报告保存吞吐、P99、首 token 延迟、错误率、中断率、共享 ARM64 主机负载和二进制摘要。并发请求共享同一 Key 的一次冷缓存凭证验证。 [本地性能报告](benchmarks/soak/results/paired-maas-arm64-local.json) · [运行说明](benchmarks/README.md)
- 两台网关使用同一公开模型别名在两个 kstack 部署之间加权选路。kstack 按签名绑定的部署 ID 和 revision 校验私有请求，模型目录和推理响应保留公开别名。本机和隔离的 Linux ARM64 容器均通过联测，按 kstack 请求记录验证 3∶1 灰度、过期 revision 拒绝、全量切至候选和回滚。回滚后在途 SSE 收到结束帧，32 条请求的批任务仍绑定原候选，额度账本和已吊销 Key 状态持续有效。 [灰度联测](tests/platform_release_e2e.py) · [配对工作流](.github/workflows/paired-maas.yml)
- MaaS 发布和回滚可通过运行中的私有控制面执行。同一公开别名关联的目录、推理和批任务选路在一个发布事务中更新。发布以预期 revision 防止并发覆盖，持久化历史权重与变更记录，并提供各副本确认的快照 revision 和摘要。本机与 Linux ARM64 联测覆盖并发发布冲突、调权期间的推理、回滚及控制面重启后的恢复。按别名回滚保留其他模型的版本。 [在线发布和回滚接口](deploy/kstack/README.md#publish-and-roll-back-model-weights) · [别名回滚测试](tests/test_maas_releases.py)
- MaaS 发布可按租户覆盖同一公开别名的目标与权重。网关从已验证的 Key 选取租户，目录、在线推理和批任务提交共享选路。双副本联测验证试点和对照租户并发调用同一别名、伪造请求头、自身版本失效与回滚期间的隔离，按 kstack 记录、用量与审计核对归属。试点回滚保留默认权重和其他租户的发布。 [租户灰度联测](tests/platform_release_e2e.py)
- kstack 的 200 节点 Linux 多进程回归中，改造前后各运行一轮 100 个部署的创建与删除。两轮均有 100 个部署进入运行状态，节点心跳无超时，服务端在部署循环分别消耗 15.1 和 15.7 CPU 秒。 [节点回归测试](../kstack/test/l2/fleet_redeploy_churn_process_test.go)

- 以 kstack 旧 Key 的前缀分批切换。联测先在旧入口完成推理，再验证 Kense Key 完成 JSON、SSE 和 token 结算。撤销试点旧 Key 后，旧推理、目录、文件和批任务返回 `401`，下一批旧 Key 仍可推理。启用 `disable_legacy_gateway` 重启后，旧入口返回 `404`，独立的 MaaS mTLS 入口继续工作。新部署的配对配置默认关闭旧入口。 [切换和回滚步骤](deploy/kstack/README.md#migrate-existing-kstack-clients) · [配对联测](tests/kstack_maas_transport.py)
- 本地真机联测通过 kstack 原生 agent 部署 Qwen2.5-0.5B-Instruct。llama.cpp 在 Apple M5 上实际卸载 25/25 层。关闭旧入口后，kgateway 和 kstack 私有 mTLS 入口各完成 32 次 JSON 和 32 次 SSE 请求，全部成功，流均正常结束，两条路径的输入和输出 token 均完成结算。 [原始报告](benchmarks/soak/results/paired-maas-apple-metal-local.json) · [复现命令](benchmarks/README.md#apple-silicon-with-actual-model-weights)

### 待验收

- 生产验收还需在目标集群以真实业务负载校准容量和灰度阈值，验证生产 KMS 与跨故障域恢复，并执行生产租户切换。

### 改名与文档清单

- **发布入口**。迁移包名、命令、帮助、`Cargo.lock`、`KGATEWAY_*`、更新器、安装脚本、归档、校验文件引用、CI、OCI、Helm 和 Homebrew。先验证目标仓库、注册表和站点发布权限，再切换下载 URL、站点 canonical 和安装入口。 [Cargo 清单](Cargo.toml) · [发布工作流](.github/workflows/release.yml)
- **配置与状态**。迁移网关自有指标、标签、注解、请求头、schema、默认路径和用户代理。已发布线协议采用版本协商与双读单写。同对端验证快照日志、未确认的用量、绑定代际和持久化标识。保留原事件 ID 和确认位点，对在途事件按既有协议排空或兼容接收。迁移结束后收紧旧值验收。第三方包名和许可署名按原始归属记录。 [快照日志](src/managed_snapshot/persistence.rs) · [用量持久化](src/usage/mod.rs)
- **旧 README、文档和站点**。删除旧双语 README、`docs/`、旧产品路线图、历史发布说明和旧站版本文档。根 README 以 `kgateway` 重写，包含架构、安装和联合部署。需要保留的发布与安全说明按新品牌重写。先将发布版本、故障演练和测试证据搬至机器可读的发布元数据及 CI，再删除依赖的旧页面。替换旧图片、社交卡片、站点元数据和旧 URL。历史实测数字随旧发行物存档，新站引用新版本证据。 [现有发布断言](tests/release_workflow.rs) · [CI 检查](.github/workflows/ci.yml)
- **发布验收**。扫描源码、生成物、用户文档和安装包内容。确认旧产品名、旧站点链接和旧图像已清理，迁移兼容和法定署名有明确来源。检查新 README 命令、站点链接与已发布文件逐一对应。

### 上线和回滚验收

- 对同一租户的两台网关做并发准入、进程重启和额度租约转移，确认总额、吊销状态和用量确认游标一致。演练控制面断连、无效快照、吊销流断连、磁盘耗尽和审计接收故障。逐项记录预期拒绝原因及上游零调用证据。
- 对账一次普通请求和一次断连请求，证明单次模型用量只有一个计量归属。模拟丢 ACK、重复投递与进程退出，核对事件无遗漏、无重复扣费。检查日志、Trace、快照和审计事件中的敏感字段。
- 用同一组负载对比端到端 P99、首 token 延迟、错误率和流中断率，按基线确定放量阈值。先单租户灰度，再按既定阈值扩大。部署包应同时支持校验配对版本、查看精确就绪状态和执行回滚。
- 路由异常时用更高 revision 恢复上版目标与权重，排空已接收的流。发行物回退使用验收过的版本对，使用兼容状态备份或迁移恢复流程，核对最新吊销、预算、在途用量和审计回执均可追踪。 [现有双副本测试](tests/managed_replica_readiness.rs) · [现有目标代际与排空测试](tests/managed_target_generation_drain.rs)

# icrypto
apple iOS system crypto framework(grpc or resultFul api)
see docs/crypto.swagger.json

base api address: https://im.app/api/v1/icrypto/

# telegram: @dxxlabc

drm only work for A7(SEP)

# 一、DeviceCertificate（UniqueDeviceCertificate）与 FairPlayKeyData 概览

1) **来源**  
- **通俗理解**：两者都是设备**激活**时由苹果服务器下发的“通行证”。*DeviceCertificate* 用来证明设备身份，*FairPlayKeyData* 用在 FairPlay 数字版权（DRM）流程里。  
- **技术要点**：二者随 **activation record** 返回，写入 Lockdown/系统组件后被上层使用（见下文）。

2) **DeviceCertificate（证书格式）**  
- **通俗理解**：一张“身份证书”，证明“这台设备是真的”。  
- **技术要点**：标准 **X.509** 证书，可用常见工具解析；参与后续会话建立/鉴别。

3) **FairPlayKeyData（用途与形态）**  
- **通俗理解**：一张“门票/会话凭证”，用于 FairPlay 的后续数据处理。  
- **技术要点**：苹果自定义的**加密/封装二进制容器**，作为**会话密钥材料/验证数据**使用；在研究与工具中可见其与本地 **IC-Info** 有严格对应关系（社区研究结论，见参考资料）。

4) **与设备的绑定关系（谨慎表述）**  
- **通俗理解**：两者与设备有绑定，但具体**强绑定**细节外部看不全。  
- **技术要点**：更深的绑定很可能在 **Secure Enclave（SEP）** 内完成：很多密钥由 **UID/GID** 硬件根密钥派生，密钥只在硬件引擎内部使用，不可导出。

---

# 二、激活流程与关键材料

1) **何时激活**  
- **通俗理解**：首次开机/刷机/抹掉后重设，设备都要向苹果**报到**拿许可证。  
- **技术要点**：设备与激活服务交互，返回 **activation record**（如 `activation_record.plist`），其中包含证书、票据、FairPlayKeyData 等，由 Lockdown/系统组件写入以完成激活。

2) **iOS 10 之前（老设备）**  
- **通俗理解**：流程较“直白”，把设备信息报上去即可。  
- **技术要点**：设备收集 **SN/IMEI/ECID/UUID/基带序列号** 等，并**同时附带** X.509 **CSR** 发给服务器；服务器返回证书 + 激活数据。

3) **iOS 10 之后（现代设备）**  
- **通俗理解**：苹果在芯片里加了一个**保险箱**——SEP，关键验证都在里面做。  
- **技术要点**：  
  - SEP 内的 **UID Key**（每台唯一）、**GID Key**（同一 SoC 家族共享）做密钥派生与签名；  
  - 增加 **drmHandshake**：嵌套证书 + 双向签名；  
  - **激活请求体由 SEP 生成并签名**，OS 仅转发。

4) **ECID 的作用**  
- **通俗理解**：相当于芯片的“DNA”，唯一且改不了。  
- **技术要点**：**ECID**（Exclusive/Unique Chip ID）为 SoC 唯一编号；个性化签名（personalization）会把 ECID 绑定进授权中，使授权**只对这台设备有效**。

5) **请求签名与篡改阻断**  
- **通俗理解**：请求被“硬件签名”，谁改谁露馅。  
- **技术要点**：含敏感字段（如 ECID）的请求体由 SEP 使用**硬件内密钥**签名；密钥不可导出，抓包/改字段会**破坏签名**，被本地或服务器拒绝。

**结论（非常重要）**：  
- **真正的“改机激活”在理论与架构上不可行**：SEP+UID/GID+ECID 的硬件绑定与个性化签名链，**从根上**阻断了“改码绕过激活”。只有在极少数早期机型（如 A7 时代）因**特定漏洞**出现例外，但这不是通用方法。

---

# 三、市场“改机”的常见误区与现实

> 仅为技术研究描述，**不构成操作建议**；绕过激活/DRM/风控可能违法并导致账号封禁或设备列入黑名单。

1) **“半改机 / BUG 改机”的本质**  
- **通俗理解**：不是把设备真的“变成另一台”，而是**障眼法**。  
- **技术要点**：  
  - 多为**上层流程劫持**，并非真正的硬件标识更改；  
  - 常见在 **iMessage 注册/登录链路**中，通过 **HOOK** 或**环境伪造**，让“上送的设备信息”**看起来像**目标，从而影响 **initializeValidation** 等初始化验证步骤；  
  - 这属于**应用层/服务层伪装**，**没有改变底层身份**（ECID/UID/GID 仍是原机）。

2) **为何不能“彻底改机”**  
- **通俗理解**：一旦需要走**完整激活**，马上露馅。  
- **技术要点**：  
  - 只要触发**重新激活/完整 DRM 握手**，就会遇到 **ECID/UID/GID** 级硬件绑定与签名校验；  
  - 这些校验在 **SEP/硬件**中完成，**抓包或用户态 patch** 都**无法伪造**；  
  - 因此所谓“彻底改机”在现代机型上**不可实现**。

3) **术语澄清：关于 “UIKCertification”**  
- **通俗理解**：这不是官方术语。  
- **技术要点**：在苹果公开资料里，常见术语是 **UID/GID、Activation Record、SHSH/APTicket、FairPlay（验证/会话）数据、IDS（iMessage）Validation Data** 等；“UIKCertification”更像**社区口语/内部命名**。建议统一用**“（iMessage/IDS）validation data”**或**“（激活）证书链/激活记录的一部分”**描述。

4) **关于“服务器长期记录 UID 证书”**  
- **通俗理解**：外界没有可靠证据证明“苹果永久存 UID 证书指纹作强匹配”。  
- **技术要点**：已知事实是 **UID/GID 不可导出，仅在硬件内使用**。会话/注册过程可能存在**状态性与信誉评估**（权重）机制，但“强绑定到固定 UID 证书”的细粒度细节**无公开权威证明**，应以**“可能/推测”**表述。

---

# 四、iMessage（IDS）注册与“权重”

1) **协议复杂度与公开资料**  
- **通俗理解**：iMessage 的加密与验证很复杂，但架构清晰。  
- **技术要点**：使用 **IDS（Identity Services）** 协议；注册需提交 **validation data（二进制验证数据）**。自 2023 年起引入 **Contact Key Verification（CKV）**，2024 年又推出 **PQ3（后量子）** 协议，提升端到端安全与抗量子能力。

2) **“权重/信誉”机制（行业共识）**  
- **通俗理解**：苹果会根据账号与设备的历史“打分”，分高更容易正常使用服务。  
- **技术要点**：虽然细节未公开，但从多方资料与实践看，账号历史、设备记录、风控信号等会影响放行。所谓“改机能发 iMessage”的现象，多为**漏洞/边界条件**下的暂时结果，**不可持续**。

3) **研究 vs 产出**  
- **通俗理解**：学术研究有价值，但对“实务改机”**没什么用**。  
- **技术要点**：协议持续演进（CKV、PQ3 等），安全投入不断加码；**产出比低**，不建议新人投入逆向以“运营”为目的。

---

# 五、术语与事实速查（面向技术同事）

- **ECID**：SoC 唯一编号；用于个性化签名/授权，使票据**只对单台设备有效**。  
- **UID/GID**：硬件根密钥，只在 AES/PKA 等**硬件引擎**内派生/使用，**不可导出**；AP/sepOS 仅能请求运算，**拿不到密钥本体**。  
- **Activation Record**：激活阶段返回的记录/票据集合（含证书、FairPlayKeyData 等），设备写入后完成激活（Lockdown 路径可见）。  
- **FairPlayKeyData ↔ IC-Info**：社区研究显示二者有**严格对应**（工具可从 activation_record 还原 IC-Info，供 FairPlay/登录等后续用）。  
- **Validation Data（IDS/iMessage）**：注册/登录时提交的二进制验证数据，是阻止非苹果设备接入的关键门槛之一。

---

# 六、合规与道德提示
本文仅用于**安全研究与科普**。试图绕过激活、DRM 或服务风控可能**违法**，并导致账号/设备封禁或列入黑名单。请勿用于任何**非授权用途**。

---

## 参考资料与延伸阅读（精选）
> 官方文档优先，其次权威研究与长期维护的技术 Wiki；社区工具与帖子仅作“研究观察”。
- **Secure Enclave / UID/GID 不可导出、仅硬件内使用**（Apple Platform Security，2024-12）：https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web  
- **UID 派生与 Keybag/Keychain 绑定**（Apple Platform Security，2024-12）：https://support.apple.com/guide/security/keybags-for-data-protection-sec6483d5760/web  
- **ECID 定义（官方）**（Apple Platform Security PDF）：https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf  
- **个性化授权：ECID 与安全更新签名**（Apple：Secure software updates）：https://support.apple.com/guide/security/secure-software-updates-secf683e0b36/web  
- **Activation Record 存放位置（取证书）**（O’Reilly《iPhone Forensics》）：https://www.oreilly.com/library/view/iphone-forensics/9780596153588/ch06s04.html  
- **APTicket/SHSH 与个性化**（The Apple Wiki：APTicket）：https://theapplewiki.com/wiki/APTicket  
- **ECID 技术条目（社区）**（The Apple Wiki：ECID）：https://theapplewiki.com/wiki/ECID  
- **FairPlayKeyData ↔ IC-Info 的社区研究**（AR2SISV）：https://github.com/j4nf4b3l/AR2SISV  
- **FairPlayKeyData ↔ IC-Info 的社区工具**（IC-info_Generator）：https://github.com/ACHKA1M/IC-info_Generator  
- **IDS/iMessage 安全总览**（Apple Platform Security：iMessage security overview）：https://support.apple.com/guide/security/imessage-security-overview-secd9764312f/web  
- **CKV：iMessage Contact Key Verification（官方博客+帮助）**：  
  - https://security.apple.com/blog/imessage-contact-key-verification/  
  - https://support.apple.com/en-us/118246  
- **PQ3：iMessage 后量子协议（官方博客+论文）**：  
  - https://security.apple.com/blog/imessage-pq3/  
  - https://security.apple.com/assets/files/A_Formal_Analysis_of_the_iMessage_PQ3_Messaging_Protocol_Basin_et_al.pdf  
  - https://www.douglas.stebila.ca/blog/archives/2024/02/21/imessage-pq3/  


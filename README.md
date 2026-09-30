# MaiBot XChat Adapter

MaiBot 的 X Chat 适配器，基于 MaiBot Plugin SDK、X API v2 Activity Stream 和 Chat XDK。

## 已支持

- X Chat 加密私信与群聊入站、出站
- 文本消息
- 图片、文件、音频、视频等媒体消息
- X Chat 三阶段媒体上传与媒体下载、解密
- Activity Stream 事件去重与断线重连
- X Chat 签名验证与会话密钥缓存

## 安装

```bash
pip install -r requirements.txt
```

将插件目录放入 MaiBot 的 `plugins/` 目录。复制并填写 `config.toml`：

鉴权二选一，已经填好的 access token 优先，OAuth2 是额外入口：

- `api.user_access_token`：手工填写的 OAuth 2.0 user token。有值时直接使用。需要 `dm.read`、`dm.write`、`tweet.read`、`users.read`、`media.write`
- `api.client_id` / `api.client_secret`：机密客户端的 OAuth 2.0 凭据。两者都填写、且没有可用 access token 时，插件在 `0.0.0.0` 上监听回调端口，把授权链接打印到日志，不会自动打开浏览器
- `api.refresh_token`：授权成功后和 access token 一起写回 `config.toml`。下次启动会在过期前自动刷新，刷新后的两个 token 仍写回原来的配置项
- `api.oauth_redirect_port`：默认 `18765`。插件在本机网卡上优先选择公网 IPv4，否则选择局域网 IPv4，并在日志中打印完整回调地址，例如 `http://192.168.1.10:18765/callback`。开发者门户里的 Callback URI 必须与这条日志完全一致
- `api.app_bearer_token`：连接 Activity Stream 和查询订阅列表，必填。按开发者门户里的原文填写。创建订阅仍用 `api.user_access_token`

授权范围固定为 `dm.read dm.write tweet.read users.read media.write offline.access`。`offline.access` 用来拿到可轮换的 refresh token。

私钥同样二选一，直接填入的 blob 优先：

- `identity.user_id`：机器人 X 用户 ID。留空时用当前 token 请求 `/2/users/me`
- `identity.signing_key_version`：已注册的 X Chat 公钥版本。使用私钥 blob 时必填；只用 PIN 时可以留空，这时选择版本号最大的公钥
- `identity.private_keys_b64`：Chat XDK `export_keys()` 产生的 Base64 私钥 blob
- `identity.juicebox_pin`：仅当私钥为空时，用这个 PIN 从 JuiceBox 备份还原私钥。PIN 不会写入日志。错误 PIN 会消耗猜测次数，连续错误约 20 次后备份永久失效

X Chat 首次身份注册需要按 X Chat XDK 文档执行 `generate_keypairs`、公钥注册和 `export_keys` 或 `setup(pin)`。适配器只加载已经注册的身份，不会在配置热更新时生成新私钥。

## 群聊

已有群聊的 ID 以 `g` 开头。适配器把它映射为 MaiBot 的 `group_info.group_id`。群名称来自会话资料或群变更事件里的标题；如果字段是密文，就用该群自己的会话密钥解密，不会把群 ID 当作名称。用户和群的昵称、头像缓存在框架分配的插件数据目录里（`data/plugins/<插件ID>/`）。群头像文件名是 `avatar/xchat/group_<群ID>`，并同步到 MaiBot 界面读取的 `data/avatar/xchat/group_<群ID>`。群密钥只挂在这个群 ID 上，成员变更带来的 key-change 会更新该群的最新密钥，不会拿群成员去代替私聊对象。昵称和头像默认缓存 72 小时（3 天），到期后再请求；时间由 `profile_cache_ttl_hours` 配置。

## 媒体

出站媒体支持 MaiBot 常见的 `raw_message` 段：

```json
{
  "type": "image",
  "data": {
    "base64": "...",
    "filename": "photo.png",
    "width": 800,
    "height": 600
  }
}
```

也支持 `data.path` 本地文件路径。适配器会使用当前会话密钥加密媒体，调用 X Chat media upload 三步接口，再把 `media_hash_key` 放入加密消息附件。

入站媒体会下载、解密并转换为 `image` 或 `file` 段，同时保留 Base64 数据和文件名。

## 限制

- X Chat 媒体下载依赖事件对应的 `key_version`；旧消息会使用对应历史密钥解密。
- Activity Stream 必须用 `api.app_bearer_token`。`GET /2/activity/subscriptions` 同样只用 app bearer：user access token 在这两个接口上会返回 403。插件用 user access token 创建 `chat.received` 和 `chat.conversation.join` 订阅（需要 `dm.read`）；关闭「忽略自己的消息」时再订阅 `chat.sent`。chat 事件用 app bearer 创建会返回 400。订阅就绪后用 app bearer 连接 `GET /2/activity/stream`。入站事件先用 `decrypt_events` 处理 `conversation_key_change_event`，校验失败时再用 `extract_conversation_keys` 取回发给自己的会话密钥，然后用 `decrypt_event` 解密 `encoded_event`。带 `webhook_id` 的订阅只走 webhook，不会当作流订阅。`backfill_minutes` 最大为 5。断线重连会按中断时长请求回溯；若接口返回无权使用该参数，插件会去掉它并立即重连实时流，避免一直 400。
- OAuth2 回调监听 `0.0.0.0`。日志里的回调主机优先用本机网卡上的公网 IPv4，否则用局域网地址；两者都没有时才回退到 `127.0.0.1`。开发者门户的 Callback URI 必须与该日志完全一致。插件只打印授权链接，不会打开浏览器。
- JuiceBox 还原使用公钥记录里的 `juicebox_config`。该版本没有备份时，需要改用 `identity.private_keys_b64`。
- 适配器当前以文本、图片和通用文件为 MaiBot 内容模型；X Chat 的特殊 reaction、reply preview 和编辑事件会被安全忽略。

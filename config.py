"""X Chat 适配器配置。"""

from __future__ import annotations

from typing import ClassVar

from maibot_sdk import Field, PluginConfigBase

from .oauth import DEFAULT_REDIRECT_PORT, DEFAULT_TIMEOUT_SEC


def _schema_i18n(
    *,
    label_en: str,
    label_ja: str,
    label_ko: str,
    hint_en: str | None = None,
    hint_ja: str | None = None,
    hint_ko: str | None = None,
    placeholder_en: str | None = None,
    placeholder_ja: str | None = None,
    placeholder_ko: str | None = None,
) -> dict[str, dict[str, str]]:
    """构造 WebUI 配置项的多语言说明文本。"""
    i18n: dict[str, dict[str, str]] = {
        "en_US": {"label": label_en},
        "ja_JP": {"label": label_ja},
        "ko_KR": {"label": label_ko},
    }
    if hint_en is not None:
        i18n["en_US"]["hint"] = hint_en
    if hint_ja is not None:
        i18n["ja_JP"]["hint"] = hint_ja
    if hint_ko is not None:
        i18n["ko_KR"]["hint"] = hint_ko
    if placeholder_en is not None:
        i18n["en_US"]["placeholder"] = placeholder_en
    if placeholder_ja is not None:
        i18n["ja_JP"]["placeholder"] = placeholder_ja
    if placeholder_ko is not None:
        i18n["ko_KR"]["placeholder"] = placeholder_ko
    return i18n


class XChatPluginConfig(PluginConfigBase):
    """插件级开关与连接参数。"""

    __ui_label__: ClassVar[str] = "插件设置"
    __ui_order__: ClassVar[int] = 0
    __ui_i18n__: ClassVar[dict[str, dict[str, str]]] = {
        "en_US": {"title": "Plugin", "description": "Enable the adapter and tune reconnect behavior."},
        "ja_JP": {"title": "プラグイン", "description": "アダプターの有効化と再接続の動作を設定します。"},
        "ko_KR": {"title": "플러그인", "description": "어댑터 사용과 재연결 동작을 설정합니다."},
    }

    enabled: bool = Field(
        default=False,
        description="是否启用 X Chat 适配器。",
        json_schema_extra={
            "hint": "关闭后插件保持空闲，不会连接 X API。",
            "i18n": _schema_i18n(
                label_en="Enable adapter",
                label_ja="アダプターを有効化",
                label_ko="어댑터 활성화",
                hint_en="When disabled, the plugin stays idle and does not connect to the X API.",
                hint_ja="無効にするとプラグインは待機したままになり、X API には接続しません。",
                hint_ko="비활성화하면 플러그인이 대기 상태로 유지되며 X API에 연결하지 않습니다.",
            ),
            "label": "启用适配器",
            "order": 0,
        },
    )
    config_version: str = Field(default="1.0.0", description="配置版本")
    reconnect_delay_sec: float = Field(
        default=5.0,
        ge=1.0,
        description="连接中断后的重连间隔。",
        json_schema_extra={
            "hint": "Activity Stream 断开后，等待这么多秒再重新连接。",
            "i18n": _schema_i18n(
                label_en="Reconnect interval (sec)",
                label_ja="再接続間隔（秒）",
                label_ko="재연결 간격(초)",
                hint_en="Seconds to wait before reconnecting after the Activity Stream drops.",
                hint_ja="Activity Stream が切断されたあと、再接続まで待つ秒数です。",
                hint_ko="Activity Stream 연결이 끊긴 뒤 다시 연결하기까지 기다릴 시간(초)입니다.",
            ),
            "label": "重连间隔（秒）",
            "order": 1,
            "step": 0.5,
        },
    )
    request_timeout_sec: float = Field(
        default=30.0,
        ge=5.0,
        description="X API 普通请求超时时间。",
        json_schema_extra={
            "hint": "普通 REST 请求的超时时间。Activity Stream 长连接不受这个值限制。",
            "i18n": _schema_i18n(
                label_en="Request timeout (sec)",
                label_ja="リクエストタイムアウト（秒）",
                label_ko="요청 제한 시간(초)",
                hint_en="Timeout for ordinary REST requests. The Activity Stream connection is not limited by this value.",
                hint_ja="通常の REST リクエストのタイムアウトです。Activity Stream の長時間接続には適用されません。",
                hint_ko="일반 REST 요청의 제한 시간입니다. Activity Stream 장기 연결에는 적용되지 않습니다.",
            ),
            "label": "请求超时（秒）",
            "order": 2,
            "step": 1,
        },
    )


class XApiConfig(PluginConfigBase):
    """X API 凭据。手填 access token 仍然有效；OAuth2 只把授权链接打印到日志，不会打开浏览器。"""

    __ui_label__: ClassVar[str] = "X API"
    __ui_order__: ClassVar[int] = 1
    __ui_i18n__: ClassVar[dict[str, dict[str, str]]] = {
        "en_US": {
            "title": "X API",
            "description": "Paste an access token, or use OAuth 2.0. The authorize URL is logged and no browser is opened. A pasted token is used as-is.",
        },
        "ja_JP": {
            "title": "X API",
            "description": "アクセストークンを貼り付けるか、OAuth 2.0 を使います。認可 URL はログに出して、ブラウザは開きません。貼り付けたトークンはそのまま使われます。",
        },
        "ko_KR": {
            "title": "X API",
            "description": "액세스 토큰을 붙여 넣거나 OAuth 2.0을 사용합니다. 인가 URL은 로그에만 출력하고 브라우저는 열지 않습니다. 직접 입력한 토큰은 그대로 사용됩니다.",
        },
    }

    user_access_token: str = Field(
        default="",
        description="OAuth 2.0 user access token。可手工填写；OAuth2 登录成功后也会写回这里。",
        json_schema_extra={
            "hint": "已填写时直接使用。需要 dm.read、dm.write、tweet.read、users.read、media.write。",
            "i18n": _schema_i18n(
                label_en="User access token",
                label_ja="ユーザーアクセストークン",
                label_ko="사용자 액세스 토큰",
                hint_en="Used as-is when present. Requires dm.read, dm.write, tweet.read, users.read, and media.write.",
                hint_ja="入力されている場合はそのまま使います。dm.read、dm.write、tweet.read、users.read、media.write が必要です。",
                hint_ko="값이 있으면 그대로 사용합니다. dm.read, dm.write, tweet.read, users.read, media.write 권한이 필요합니다.",
                placeholder_en="Paste an OAuth 2.0 user access token",
                placeholder_ja="OAuth 2.0 ユーザーアクセストークンを貼り付け",
                placeholder_ko="OAuth 2.0 사용자 액세스 토큰 붙여넣기",
            ),
            "input_type": "password",
            "label": "User access token",
            "order": 0,
            "password": True,
            "placeholder": "粘贴 OAuth 2.0 user access token",
        },
    )
    refresh_token: str = Field(
        default="",
        description="OAuth2 refresh token。授权成功后自动写回，也可手工填写。",
        json_schema_extra={
            "hint": "配合 Client ID / Client Secret，在 access token 过期前自动刷新。只填写 access token 时不会使用这个字段。",
            "i18n": _schema_i18n(
                label_en="Refresh token",
                label_ja="リフレッシュトークン",
                label_ko="리프레시 토큰",
                hint_en="With Client ID and Client Secret, refreshes the access token before it expires. Ignored when only an access token is configured.",
                hint_ja="Client ID と Client Secret がある場合、期限前にアクセストークンを更新します。アクセストークンだけのときは使いません。",
                hint_ko="Client ID와 Client Secret이 있으면 만료 전에 액세스 토큰을 갱신합니다. 액세스 토큰만 있는 경우에는 사용하지 않습니다.",
                placeholder_en="Filled automatically after OAuth 2.0",
                placeholder_ja="OAuth 2.0 後に自動入力されます",
                placeholder_ko="OAuth 2.0 이후 자동으로 채워집니다",
            ),
            "input_type": "password",
            "label": "Refresh token",
            "order": 1,
            "password": True,
            "placeholder": "OAuth2 成功后自动写回",
        },
    )
    client_id: str = Field(
        default="",
        description="X 应用的 OAuth 2.0 Client ID。与 Client Secret 一起填写后，缺少可用 access token 时在日志中打印授权链接。",
        json_schema_extra={
            "hint": "在 developer.x.com 的 Keys and tokens 中查看。插件不会打开浏览器。回调地址形如 http://<本机公网或局域网 IP>:<端口>/callback，以日志为准。",
            "i18n": _schema_i18n(
                label_en="Client ID",
                label_ja="Client ID",
                label_ko="Client ID",
                hint_en="From Keys and tokens on developer.x.com. The plugin logs the authorize URL and does not open a browser. The callback looks like http://<public or LAN IPv4>:<port>/callback and is printed in the log.",
                hint_ja="developer.x.com の Keys and tokens にあります。プラグインはブラウザを開かず、認可 URL をログに出します。コールバックは http://<グローバルまたは LAN の IPv4>:<ポート>/callback で、ログの表示が正です。",
                hint_ko="developer.x.com의 Keys and tokens에서 확인합니다. 플러그인은 브라우저를 열지 않고 인가 URL을 로그에 출력합니다. 콜백은 http://<공인 또는 LAN IPv4>:<포트>/callback 이며 로그에 나온 주소가 기준입니다.",
                placeholder_en="OAuth 2.0 Client ID",
                placeholder_ja="OAuth 2.0 Client ID",
                placeholder_ko="OAuth 2.0 Client ID",
            ),
            "label": "Client ID",
            "order": 2,
            "placeholder": "OAuth 2.0 Client ID",
        },
    )
    client_secret: str = Field(
        default="",
        description="X 应用的 OAuth 2.0 Client Secret。仅机密客户端（Web App 或 Bot）会提供。",
        json_schema_extra={
            "hint": "和 Client ID 成对使用。授权范围固定为 dm.read、dm.write、tweet.read、users.read、media.write、offline.access。",
            "i18n": _schema_i18n(
                label_en="Client Secret",
                label_ja="Client Secret",
                label_ko="Client Secret",
                hint_en="Paired with Client ID. Scopes are fixed to dm.read, dm.write, tweet.read, users.read, media.write, and offline.access.",
                hint_ja="Client ID と対で使います。スコープは dm.read、dm.write、tweet.read、users.read、media.write、offline.access に固定です。",
                hint_ko="Client ID와 함께 사용합니다. 범위는 dm.read, dm.write, tweet.read, users.read, media.write, offline.access 로 고정됩니다.",
                placeholder_en="OAuth 2.0 Client Secret",
                placeholder_ja="OAuth 2.0 Client Secret",
                placeholder_ko="OAuth 2.0 Client Secret",
            ),
            "input_type": "password",
            "label": "Client Secret",
            "order": 3,
            "password": True,
            "placeholder": "OAuth 2.0 Client Secret",
        },
    )
    oauth_redirect_port: int = Field(
        default=DEFAULT_REDIRECT_PORT,
        ge=1,
        le=65535,
        description="OAuth2 回调端口。插件在 0.0.0.0 上监听，日志中的回调主机是本机网卡上的公网或局域网 IPv4。",
        json_schema_extra={
            "hint": "开发者门户的 Callback URI 必须与日志中的 http://<该地址>:<这个端口>/callback 完全一致。",
            "i18n": _schema_i18n(
                label_en="OAuth callback port",
                label_ja="OAuth コールバックポート",
                label_ko="OAuth 콜백 포트",
                hint_en="The developer portal Callback URI must exactly match the logged http://<that address>:<this port>/callback.",
                hint_ja="開発者ポータルの Callback URI は、ログに出る http://<そのアドレス>:<このポート>/callback と完全一致させてください。",
                hint_ko="개발자 포털의 Callback URI는 로그에 출력된 http://<해당 주소>:<이 포트>/callback 과 정확히 같아야 합니다.",
            ),
            "label": "OAuth 回调端口",
            "order": 4,
        },
    )
    oauth_timeout_sec: float = Field(
        default=float(DEFAULT_TIMEOUT_SEC),
        ge=30.0,
        le=900.0,
        description="等待用户打开日志中的授权链接并完成授权的最长时间。",
        json_schema_extra={
            "hint": "超时后本次启动不会再次打印授权链接。重新加载插件或保存配置后再试。",
            "i18n": _schema_i18n(
                label_en="OAuth timeout (sec)",
                label_ja="OAuth タイムアウト（秒）",
                label_ko="OAuth 제한 시간(초)",
                hint_en="After a timeout this startup does not print the authorize URL again. Reload the plugin or save the config to retry.",
                hint_ja="時間切れのあと、この起動では認可 URL を再出力しません。プラグインの再読み込みか設定の保存で再試行します。",
                hint_ko="시간이 초과되면 이번 시작에서는 인가 URL을 다시 출력하지 않습니다. 플러그인을 다시 불러오거나 설정을 저장한 뒤 다시 시도하세요.",
            ),
            "label": "OAuth 等待时间（秒）",
            "order": 5,
            "step": 10,
        },
    )
    app_bearer_token: str = Field(
        default="",
        description="App-only Bearer Token。连接 Activity Stream 和查询订阅列表时使用。",
        json_schema_extra={
            "hint": "必填。user access token 只能创建订阅；用它连接 stream 或查询订阅会被拒绝。按开发者门户中的原文填写。",
            "i18n": _schema_i18n(
                label_en="App Bearer token",
                label_ja="アプリ Bearer トークン",
                label_ko="앱 Bearer 토큰",
                hint_en="Required. The user access token only creates subscriptions. The stream and the subscription list reject it. Paste the portal value unchanged.",
                hint_ja="必須です。ユーザーアクセストークンは購読の作成だけに使います。ストリームと購読一覧はそれを拒否します。ポータルの値をそのまま貼ってください。",
                hint_ko="필수입니다. 사용자 액세스 토큰은 구독 생성에만 쓰입니다. 스트림과 구독 목록은 그 토큰을 거부합니다. 포털의 값을 그대로 붙여 넣으세요.",
                placeholder_en="App-only bearer token",
                placeholder_ja="App-only Bearer トークン",
                placeholder_ko="App-only Bearer 토큰",
            ),
            "input_type": "password",
            "label": "App Bearer token",
            "order": 6,
            "password": True,
            "placeholder": "App-only Bearer Token",
        },
    )
    access_token_expires_at: int = Field(
        default=0,
        description="OAuth2 access token 的过期时间（Unix 秒）。0 表示未知，不会主动刷新。",
        json_schema_extra={
            "disabled": True,
            "hidden": True,
            "i18n": _schema_i18n(
                label_en="Access token expiry",
                label_ja="アクセストークンの有効期限",
                label_ko="액세스 토큰 만료 시각",
                hint_en="Unix seconds. 0 means unknown, so a pasted token is not refreshed on a timer.",
                hint_ja="Unix 秒です。0 は不明を意味し、貼り付けたトークンはタイマーでは更新しません。",
                hint_ko="Unix 초입니다. 0은 알 수 없음이며, 붙여 넣은 토큰은 타이머로 갱신하지 않습니다.",
            ),
            "label": "Access token 过期时间",
            "order": 99,
        },
    )


class XIdentityConfig(PluginConfigBase):
    """X Chat 身份。私钥 blob 优先于 JuiceBox PIN。"""

    __ui_label__: ClassVar[str] = "X Chat 身份"
    __ui_order__: ClassVar[int] = 2
    __ui_i18n__: ClassVar[dict[str, dict[str, str]]] = {
        "en_US": {
            "title": "X Chat identity",
            "description": "Load an exported private-key blob, or recover one with the JuiceBox PIN. The blob wins when both are set.",
        },
        "ja_JP": {
            "title": "X Chat の身元",
            "description": "書き出した秘密鍵 blob を読み込むか、JuiceBox PIN で復元します。両方ある場合は blob を優先します。",
        },
        "ko_KR": {
            "title": "X Chat 신원",
            "description": "내보낸 개인 키 blob를 불러오거나 JuiceBox PIN으로 복원합니다. 둘 다 있으면 blob를 우선합니다.",
        },
    }

    user_id: str = Field(
        default="",
        description="机器人 X 用户 ID。留空时用当前 token 调用 /2/users/me 解析。",
        json_schema_extra={
            "hint": "数字 ID，不是 @用户名。",
            "i18n": _schema_i18n(
                label_en="User ID",
                label_ja="ユーザー ID",
                label_ko="사용자 ID",
                hint_en="Numeric ID, not the @handle. Leave empty to resolve it from /2/users/me.",
                hint_ja="数字の ID です。@ユーザー名ではありません。空なら /2/users/me から解決します。",
                hint_ko="숫자 ID이며 @사용자명이 아닙니다. 비워 두면 /2/users/me 에서 확인합니다.",
                placeholder_en="2244994945",
                placeholder_ja="2244994945",
                placeholder_ko="2244994945",
            ),
            "label": "用户 ID",
            "order": 0,
            "placeholder": "2244994945",
        },
    )
    signing_key_version: str = Field(
        default="",
        description="已注册 X Chat 公钥的 public_key_version。",
        json_schema_extra={
            "hint": "使用私钥 blob 时必填。只用 JuiceBox PIN 时可以留空，这时会选择版本号最大的公钥。",
            "i18n": _schema_i18n(
                label_en="Signing key version",
                label_ja="署名鍵のバージョン",
                label_ko="서명 키 버전",
                hint_en="Required with a private-key blob. Optional for JuiceBox PIN recovery; the highest public_key_version is used.",
                hint_ja="秘密鍵 blob を使うときは必須です。JuiceBox PIN だけなら空でもよく、その場合は最大の public_key_version を使います。",
                hint_ko="개인 키 blob를 쓸 때는 필수입니다. JuiceBox PIN만 사용할 때는 비워 둘 수 있으며, 가장 큰 public_key_version을 사용합니다.",
                placeholder_en="1",
                placeholder_ja="1",
                placeholder_ko="1",
            ),
            "label": "Signing key version",
            "order": 1,
            "placeholder": "1",
        },
    )
    private_keys_b64: str = Field(
        default="",
        description="Chat XDK export_keys 输出的 Base64 私钥 blob。填写后优先使用，不会尝试 JuiceBox。",
        json_schema_extra={
            "hint": "与 JuiceBox PIN 二选一。这里有值时忽略 PIN，避免消耗 JuiceBox 猜测次数。",
            "i18n": _schema_i18n(
                label_en="Private keys (Base64)",
                label_ja="秘密鍵（Base64）",
                label_ko="개인 키(Base64)",
                hint_en="Alternative to the JuiceBox PIN. When this is set, the PIN is ignored so no JuiceBox guess is spent.",
                hint_ja="JuiceBox PIN との二者択一です。ここを入力すると PIN は無視され、JuiceBox の試行回数を消費しません。",
                hint_ko="JuiceBox PIN과 둘 중 하나입니다. 여기에 값이 있으면 PIN은 무시되며 JuiceBox 추측 횟수를 소모하지 않습니다.",
                placeholder_en="Base64 export_keys blob",
                placeholder_ja="Base64 の export_keys blob",
                placeholder_ko="Base64 export_keys blob",
            ),
            "input_type": "password",
            "label": "Private keys（Base64）",
            "order": 2,
            "password": True,
            "placeholder": "Base64 export_keys blob",
        },
    )
    juicebox_pin: str = Field(
        default="",
        description="用 JuiceBox PIN 从 X 的密钥备份还原私钥。仅在 Private keys 为空时使用。",
        json_schema_extra={
            "hint": "PIN 不会写入日志。错误 PIN 会消耗猜测次数，连续错误约 20 次后该备份会永久失效。",
            "i18n": _schema_i18n(
                label_en="JuiceBox PIN",
                label_ja="JuiceBox PIN",
                label_ko="JuiceBox PIN",
                hint_en="The PIN is not logged. A wrong PIN spends a guess; about 20 failures permanently delete that backup.",
                hint_ja="PIN はログに残りません。間違った PIN は試行回数を消費し、約 20 回失敗するとそのバックアップは永久に失われます。",
                hint_ko="PIN은 로그에 남지 않습니다. 틀린 PIN은 추측 횟수를 소모하며, 약 20회 실패하면 해당 백업이 영구적으로 삭제됩니다.",
                placeholder_en="4-digit X Chat PIN",
                placeholder_ja="4 桁の X Chat PIN",
                placeholder_ko="4자리 X Chat PIN",
            ),
            "input_type": "password",
            "label": "JuiceBox PIN",
            "order": 3,
            "password": True,
            "placeholder": "X Chat PIN",
        },
    )


class XChatSettings(PluginConfigBase):
    """X Chat 适配器完整配置。"""

    plugin: XChatPluginConfig = Field(default_factory=XChatPluginConfig)
    api: XApiConfig = Field(default_factory=XApiConfig)
    identity: XIdentityConfig = Field(default_factory=XIdentityConfig)
    ignore_self_messages: bool = Field(
        default=True,
        description="是否忽略 Activity Stream 中机器人自己的 chat.sent 事件。",
        json_schema_extra={
            "hint": "关闭后，机器人发出的消息也会进入 MaiBot。",
            "i18n": _schema_i18n(
                label_en="Ignore own messages",
                label_ja="自分のメッセージを無視",
                label_ko="자신의 메시지 무시",
                hint_en="When off, messages sent by the bot are also delivered to MaiBot.",
                hint_ja="オフにすると、ボット自身が送ったメッセージも MaiBot に渡されます。",
                hint_ko="끄면 봇이 보낸 메시지도 MaiBot으로 전달됩니다.",
            ),
            "label": "忽略自己的消息",
            "order": 1,
        },
    )
    backfill_minutes: int = Field(
        default=0,
        ge=0,
        le=5,
        description="Activity Stream 首次连接时请求的回溯分钟数。",
        json_schema_extra={
            "hint": "0 表示首次连接不回溯。接口最多接受 5 分钟。断线重连会按中断时长补拉，同样不超过 5 分钟。若接口返回无权使用该参数，则去掉它并保持实时连接。",
            "i18n": _schema_i18n(
                label_en="Backfill (minutes)",
                label_ja="バックフィル（分）",
                label_ko="백필(분)",
                hint_en="0 skips backfill on the first connection. The API accepts at most 5 minutes. Reconnects request the gap, also capped at 5 minutes. If the stream is not authorized for this parameter, later connections omit it and stay live.",
                hint_ja="0 なら初回接続ではバックフィルしません。API の上限は 5 分です。再接続時は切断時間ぶんを要求し、同じく 5 分までです。このパラメータの権限がない場合は外してライブ接続を維持します。",
                hint_ko="0이면 첫 연결에서 백필하지 않습니다. API는 최대 5분입니다. 재연결 때는 끊긴 시간만큼 요청하며 역시 5분을 넘지 않습니다. 이 파라미터 권한이 없으면 빼고 실시간 연결을 유지합니다.",
            ),
            "label": "回溯分钟数",
            "order": 2,
        },
    )
    max_message_length: int = Field(
        default=10000,
        ge=1,
        le=100000,
        description="单条消息送入 MaiBot 前的最大字符数。",
        json_schema_extra={
            "hint": "超出的入站文本会被截断。",
            "i18n": _schema_i18n(
                label_en="Max message length",
                label_ja="メッセージ最大長",
                label_ko="최대 메시지 길이",
                hint_en="Longer inbound text is truncated before it reaches MaiBot.",
                hint_ja="これより長い受信テキストは MaiBot に渡す前に切り詰めます。",
                hint_ko="더 긴 수신 텍스트는 MaiBot에 전달하기 전에 잘라냅니다.",
            ),
            "label": "最大消息长度",
            "order": 3,
        },
    )
    profile_cache_ttl_hours: int = Field(
        default=72,
        ge=1,
        le=24 * 30,
        description="用户和群的昵称、头像缓存时间。",
        json_schema_extra={
            "hint": "到期后重新读取。默认 72 小时，也就是 3 天。用户资料按次计费，所以同一个人或同一个群在到期前只请求一次。",
            "i18n": _schema_i18n(
                label_en="Profile cache (hours)",
                label_ja="プロフィールキャッシュ（時間）",
                label_ko="프로필 캐시(시간)",
                hint_en="Nicknames and avatars for users and groups are fetched again after this many hours. The default is 72 hours, which is 3 days. User lookups are metered, so each person or group is requested once per window.",
                hint_ja="ユーザーとグループの表示名とアイコンを、この時間のあと再取得します。既定は 72 時間（3 日）です。ユーザー情報は従量なので、期限までは一人または一つのグループにつき 1 回だけリクエストします。",
                hint_ko="사용자와 그룹의 닉네임과 아바타를 이 시간이 지난 뒤 다시 가져옵니다. 기본값은 72시간, 즉 3일입니다. 사용자 조회는 종량이므로 만료 전에는 사람 또는 그룹마다 한 번만 요청합니다.",
            ),
            "label": "资料缓存（小时）",
            "order": 4,
        },
    )

    def should_connect(self) -> bool:
        return self.plugin.enabled

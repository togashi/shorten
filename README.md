# shorten

UUID やハッシュをできるだけ短いテキストで表現したかったコマンドラインツール

## 例

デフォルトエンコーディング (Base32)
```shell
> shorten cc4350a9-a41a-40dc-ad7a-14f862050eb4
ZRBVBKNEDJANZLL2CT4GEBIOWQ
```

ショーケース
```shell
> shorten -e showcase cc4350a9-a41a-40dc-ad7a-14f862050eb4
Hex(thru): cc4350a9a41a40dcad7a14f862050eb4
Base32:    ZRBVBKNEDJANZLL2CT4GEBIOWQ
Base36:    C3CCIS59NYBO7C7WOTUBRQJZO
Base56:    sXYeLq2eEmwkBy0eLa0BeM
Base58:    SDx3fzhyWMQWPLAkj6fTFZ
Base62:    06QBihPF61K3ApBppC1QMD
Base64:    zENQqaQaQNytehT4YgUOtA
Base64url: zENQqaQaQNytehT4YgUOtA
Ascii85:   %tKJAq#8int$GyrVg(Mg
Z85:       +TkjaQ-8INT:gYRvG^mG
```

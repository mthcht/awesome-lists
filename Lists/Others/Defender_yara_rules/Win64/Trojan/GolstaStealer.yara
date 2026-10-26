rule Trojan_Win64_GolstaStealer_AG_2147980951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GolstaStealer.AG!MTB"
        threat_id = "2147980951"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GolstaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "golsta/cmd/client" ascii //weight: 3
        $x_2_2 = "golsta" ascii //weight: 2
        $x_1_3 = "github.com/HokageRegard/excrypto" ascii //weight: 1
        $x_1_4 = "steaminfo.txt" ascii //weight: 1
        $x_1_5 = "useragent.txt" ascii //weight: 1
        $x_1_6 = "accounts.json" ascii //weight: 1
        $x_1_7 = "discordcanary" ascii //weight: 1
        $x_1_8 = "BetterDiscord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


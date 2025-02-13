rule Trojan_MSIL_Icarus_AI_2147838190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Icarus.AI!MTB"
        threat_id = "2147838190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Icarus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "aHR0cDovLzE5My4zMS4xMTYuMjM5L2NyeXB0L3B1YmxpYy9VcGRhdGVfRG93bmxvYWRzL0ljYXIuanBn" wide //weight: 2
        $x_2_2 = "aHR0cDovLzE5My4zMS4xMTYuMjM5L2NyeXB0L3B1YmxpYy9VcGRhdGVfRG93bmxvYWRzL3J0LmpwZw==" wide //weight: 2
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Icar.jpg" wide //weight: 1
        $x_1_5 = "Icarus.zip" wide //weight: 1
        $x_1_6 = "taskkill /F /IM chrome.exe" wide //weight: 1
        $x_1_7 = "taskkill /F /IM firefox.exe" wide //weight: 1
        $x_1_8 = "taskkill /F /IM waterfox.exe" wide //weight: 1
        $x_1_9 = "taskkill /F /IM msinfo32.exe" wide //weight: 1
        $x_1_10 = "taskkill /F /IM putty.exe" wide //weight: 1
        $x_1_11 = "taskkill /F /IM ArmoryQt.exe" wide //weight: 1
        $x_1_12 = "taskkill /F /IM DingTalkLite.exe" wide //weight: 1
        $x_1_13 = "taskkill /F /IM Atomic Wallet.exe" wide //weight: 1
        $x_1_14 = "taskkill /F /IM mstsc.exe" wide //weight: 1
        $x_1_15 = "taskkill /F /IM Coinomi.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_2_*) and 11 of ($x_1_*))) or
            (all of ($x*))
        )
}


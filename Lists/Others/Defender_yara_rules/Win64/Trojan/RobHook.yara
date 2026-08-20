rule Trojan_Win64_RobHook_MKV_2147976502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RobHook.MKV!MTB"
        threat_id = "2147976502"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RobHook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".ROBLOSECURITY" ascii //weight: 3
        $x_3_2 = "wallet.dat" ascii //weight: 3
        $x_3_3 = "Login Data" ascii //weight: 3
        $x_3_4 = "exodus.wallet" ascii //weight: 3
        $x_2_5 = "MetaMask" ascii //weight: 2
        $x_2_6 = "leveldb" ascii //weight: 2
        $x_2_7 = "discord" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


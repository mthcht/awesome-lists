rule Ransom_Win32_SpyroCrypt_PA_2147783641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SpyroCrypt.PA!MTB"
        threat_id = "2147783641"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyroCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Spyro" ascii //weight: 1
        $x_1_2 = "BlackSpyro" ascii //weight: 1
        $x_1_3 = "fuckyoufuckyou" ascii //weight: 1
        $x_1_4 = "Decrypt-info.txt" wide //weight: 1
        $x_1_5 = "netsh firewall set opmode mode=disable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


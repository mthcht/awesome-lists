rule Trojan_Win32_PassView_SIBA_2147798539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PassView.SIBA!MTB"
        threat_id = "2147798539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PassView"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "AppData\\Local\\Microsoft\\Vault\\4BF4C442-9B8A-41A0-B380-DD4A704DDB2" ascii //weight: 5
        $x_5_2 = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"" ascii //weight: 5
        $x_1_3 = "iepv_sites.txt" ascii //weight: 1
        $x_50_4 = {33 db 88 1f 8a 06 84 c0 b1 ?? 2a cb 32 c8 6a ?? 8d 45 ?? 50 80 f1 ?? 57 88 4d 04 e8 ?? ?? ?? ?? 83 c4 0c 43 8a 04 33 84 c0 75}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}


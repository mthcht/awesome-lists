rule Ransom_Win32_Shadowlock_YBE_2147959772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Shadowlock.YBE!MTB"
        threat_id = "2147959772"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Shadowlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR EMPIRE IS ASHES" ascii //weight: 1
        $x_1_2 = "ENTER PASSWORD TO UNLOCK" ascii //weight: 1
        $x_1_3 = "SHADOWLOCK" ascii //weight: 1
        $x_1_4 = "PAY OR DIE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


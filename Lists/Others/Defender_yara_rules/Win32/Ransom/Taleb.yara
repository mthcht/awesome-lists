rule Ransom_Win32_Taleb_PAA_2147793510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Taleb.PAA!MTB"
        threat_id = "2147793510"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Taleb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\prvkey.txt" ascii //weight: 1
        $x_1_3 = "fuckyoufuckyou" ascii //weight: 1
        $x_1_4 = "Files Has Been Encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


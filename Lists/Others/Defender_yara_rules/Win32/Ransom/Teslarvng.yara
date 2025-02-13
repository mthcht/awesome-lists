rule Ransom_Win32_Teslarvng_PB_2147787772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teslarvng.PB!MTB"
        threat_id = "2147787772"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teslarvng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\windows\\system32\\sc.exe" wide //weight: 1
        $x_1_2 = "teslarvng" wide //weight: 1
        $x_1_3 = "\" start= auto" wide //weight: 1
        $x_1_4 = "binpath= \"" wide //weight: 1
        $x_1_5 = "defragsrv" wide //weight: 1
        $x_1_6 = "create" wide //weight: 1
        $x_1_7 = "start" wide //weight: 1
        $x_1_8 = "-is" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


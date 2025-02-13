rule Trojan_Win32_Genasom_2147750660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Genasom!MSR"
        threat_id = "2147750660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 2
        $x_2_2 = "bcdedit.exe /set {default} recoveryenabled no" ascii //weight: 2
        $x_2_3 = "bcdedit.exe /set {current} bootstatuspolicy ignoreallfailures" ascii //weight: 2
        $x_1_4 = "LOOK.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


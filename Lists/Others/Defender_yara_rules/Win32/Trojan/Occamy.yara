rule Trojan_Win32_Occamy_AMAB_2147853392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Occamy.AMAB!MTB"
        threat_id = "2147853392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Occamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\2890.tmp\\1.bat" ascii //weight: 1
        $x_1_2 = "C:\\TEMP\\2891.tmp" ascii //weight: 1
        $x_1_3 = "%temp%\\popup.sed" ascii //weight: 1
        $x_1_4 = "extd.exe" ascii //weight: 1
        $x_1_5 = "set ppopup_executable=popupe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Occamy_NC_2147899959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Occamy.NC!MTB"
        threat_id = "2147899959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Occamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {eb d8 ff 96 ?? ?? ?? ?? 83 c7 04 8d 5e fc 31 c0 8a 07 47 09 c0 74 22 3c ef}  //weight: 5, accuracy: Low
        $x_1_2 = "Lmkmejmz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


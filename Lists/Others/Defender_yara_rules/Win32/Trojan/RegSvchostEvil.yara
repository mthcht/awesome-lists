rule Trojan_Win32_RegSvchostEvil_2147963847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegSvchostEvil"
        threat_id = "2147963847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegSvchostEvil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "/v cymtest /t" wide //weight: 15
        $x_1_2 = "dllname" wide //weight: 1
        $x_1_3 = "cmd.exe" wide //weight: 1
        $x_1_4 = " reg_sz /v" wide //weight: 1
        $x_4_5 = "hkey_local_machine\\software\\microsoft\\windows\\currentversion\\runservices /v" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Bladab_HAZ_2147750666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bladab.HAZ!MTB"
        threat_id = "2147750666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "objShell.Run \"\"\"%appdata%\\systemUpdate\\partner.vbs\"\"\" , 0, True" ascii //weight: 1
        $x_1_2 = "nslookup myip.opendns.com. resolver1.opendns.com" ascii //weight: 1
        $x_1_3 = "51.89.237.234" ascii //weight: 1
        $x_1_4 = "sushi/pages/controllers/session_controller.php" ascii //weight: 1
        $x_1_5 = "\\pdfReader\\paidard.vbs  \\pdfReader\\paidard.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


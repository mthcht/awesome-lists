rule Trojan_Win32_XBaiBrowser_2147900431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XBaiBrowser"
        threat_id = "2147900431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XBaiBrowser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xbsetup-p.pdb" ascii //weight: 1
        $x_1_2 = "Image File Execution Options\\msedge.exe" wide //weight: 1
        $x_1_3 = "SOFTWARE\\xbaibrowser" wide //weight: 1
        $x_1_4 = "xbsetup_instance" wide //weight: 1
        $x_1_5 = "-setdb -wnd %u -msg %u -br" wide //weight: 1
        $x_1_6 = "https://www.minibai.com/agreement.html" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


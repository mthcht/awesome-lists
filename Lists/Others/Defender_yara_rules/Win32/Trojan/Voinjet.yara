rule Trojan_Win32_Voinjet_A_2147710546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Voinjet.A"
        threat_id = "2147710546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Voinjet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "document.body.insertBefore(adpro, document.body.children.item(0))" ascii //weight: 1
        $x_1_2 = "text|password|file" ascii //weight: 1
        $x_1_3 = {00 2e 65 78 65 00 73 76 63 68 6f 73 74 2e 65 78 65 00 2a 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "Microsoft* Windows* Operating System" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


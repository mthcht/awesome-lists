rule Trojan_Win32_Affpach_A_2147657301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Affpach.A"
        threat_id = "2147657301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Affpach"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3CC8EBC7-CFDD-4BA0-A1D1-F4AFB855A715" ascii //weight: 1
        $x_1_2 = "document.getElementById('su').removeNode(true)" ascii //weight: 1
        $x_1_3 = "IETASK.pdb" ascii //weight: 1
        $x_1_4 = "/go/act/mmbd/pd01.php?pid=" ascii //weight: 1
        $x_1_5 = {26 63 68 3d 35 26 62 61 72 3d 26 77 64 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


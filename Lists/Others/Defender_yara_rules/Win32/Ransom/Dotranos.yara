rule Ransom_Win32_Dotranos_A_2147720276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dotranos.A"
        threat_id = "2147720276"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dotranos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "&bitcoinAddress=" ascii //weight: 1
        $x_1_3 = "</a><br><a class=\"submit\"href=\"https://" ascii //weight: 1
        $x_1_4 = "<title>Your data was locked!</title>" ascii //weight: 1
        $x_1_5 = "(bootsect.bak|iconcache.db|ntuser.dat|thumbs.db|activationstore.dat|microsoft)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


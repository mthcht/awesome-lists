rule Ransom_Win32_VCrypt_2147725537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VCrypt"
        threat_id = "2147725537"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\get_my_files.txt" ascii //weight: 2
        $x_2_2 = "*** ALL YOUR WORK AND PERSONAL FILES HAVE BEEN ENCRYPTED ***" ascii //weight: 2
        $x_2_3 = "To decrypt your files you need to buy the special software" ascii //weight: 2
        $x_2_4 = "jz3sncvmveprhihk.onion (need Tor-browser)" ascii //weight: 2
        $x_2_5 = "jz3sncvmveprhihk.onion.rip" ascii //weight: 2
        $x_2_6 = "jz3sncvmveprhihk.onion.cab" ascii //weight: 2
        $x_2_7 = "jz3sncvmveprhihk.hiddenservice.net" ascii //weight: 2
        $x_2_8 = "davidfreemon2@aol.com" ascii //weight: 2
        $x_2_9 = {64 61 76 69 64 00 2e 64 61 76 69 64 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_VCrypt_2147754579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VCrypt!MTB"
        threat_id = "2147754579"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://gisele.liroy.free.fr/bitmap" ascii //weight: 1
        $x_1_2 = "%PUBLIC%\\public_user.vcrypt" ascii //weight: 1
        $x_1_3 = "%_music.vcrypt" ascii //weight: 1
        $x_1_4 = {64 6f 20 22 25 54 45 4d 50 25 5c [0-8] 2e 65 78 65 22 20 61 20 2d 74 37 7a 20 2d 72 20 2d 6d 78 30 20 2d [0-224] 20}  //weight: 1, accuracy: Low
        $x_1_5 = {54 6f 75 73 20 76 6f 73 20 66 69 63 68 69 65 72 73 20 6f 6e 74 20 c3 a9 74 c3 a9 73 20 63 68 69 66 66 72 c3 a9 73 20 65 74 20 70 6c 61 63 c3 a9 73 20 64 61 6e 73 20 75 6e 65 20 7a 6f 6e 65 20 64 65 20 73 c3 a9 63 75 72 69 74 c3 a9 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


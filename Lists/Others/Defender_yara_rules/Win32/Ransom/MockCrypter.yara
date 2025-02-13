rule Ransom_Win32_MockCrypter_PA_2147773767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MockCrypter.PA!MTB"
        threat_id = "2147773767"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MockCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Executing a Mock Ransomware....." ascii //weight: 1
        $x_1_2 = "www.makup0000.com" ascii //weight: 1
        $x_1_3 = "\\@ Please_Read_Me @ .txt" ascii //weight: 1
        $x_1_4 = "Your files are encrypted" ascii //weight: 1
        $x_1_5 = {5c 4d 6f 63 6b 52 61 6e 73 6f 6d 65 77 61 72 65 5c [0-16] 5c 4d 6f 63 6b 52 61 6e 73 6f 6d 65 77 61 72 65 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


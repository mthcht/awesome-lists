rule Trojan_Win64_FileCrypter_LVK_2147969751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCrypter.LVK!MTB"
        threat_id = "2147969751"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 d0 89 c2 80 34 13 5a 8d 50 01 39 ca 73 3b 80 34 13 5a 8d 50 02 39 ca 73 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCrypter_SX_2147974673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCrypter.SX!MTB"
        threat_id = "2147974673"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "[+] If you see this, the payload executed" ascii //weight: 15
        $x_10_2 = "Hello from CC Crypter test payload" ascii //weight: 10
        $x_7_3 = "CC Crypter - LO's Lab" ascii //weight: 7
        $x_2_4 = "[+] Process ID :" ascii //weight: 2
        $x_1_5 = "[+] Module Base: 0x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


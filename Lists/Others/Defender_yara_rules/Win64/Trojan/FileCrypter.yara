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

rule Trojan_Win64_FileCrypter_LR_2147980460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCrypter.LR!MTB"
        threat_id = "2147980460"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {41 8b c2 41 f7 e1 c1 ea 04 0f b7 c2 6b c8 31 41 0f b7 c1 66 2b c1 66 41 03 c3 66 42 31 44 4d a0 44 03 cb}  //weight: 20, accuracy: High
        $x_2_2 = "%s\\wallhaven-%s.png" ascii //weight: 2
        $x_3_3 = "%s\\spray-%016llx.png" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


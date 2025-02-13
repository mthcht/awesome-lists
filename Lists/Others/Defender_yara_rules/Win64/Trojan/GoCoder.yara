rule Trojan_Win64_GoCoder_MA_2147844481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoCoder.MA!MTB"
        threat_id = "2147844481"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "bc1qqxck7kpzgvud7v2hfyk55yr45fnml4rmt3jasz" ascii //weight: 5
        $x_1_2 = "private key is not right. contact your administrator" ascii //weight: 1
        $x_1_3 = "ITSSHOWKEY" ascii //weight: 1
        $x_1_4 = "enc done !" ascii //weight: 1
        $x_1_5 = "public.txt" ascii //weight: 1
        $x_1_6 = "decrypt file" ascii //weight: 1
        $x_1_7 = "I am so sorry ! All your files have been encryptd by RSA-1024" ascii //weight: 1
        $x_1_8 = "else you can delete your encrypted data or reinstall" ascii //weight: 1
        $x_1_9 = "you not own bitcoin,you can buy it online on some websites" ascii //weight: 1
        $x_1_10 = "email ITSEMAIL . i will send you decrytion tool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


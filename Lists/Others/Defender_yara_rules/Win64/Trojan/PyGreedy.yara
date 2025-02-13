rule Trojan_Win64_PyGreedy_YAA_2147921054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PyGreedy.YAA!MTB"
        threat_id = "2147921054"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PyGreedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "If you are looking at this is because you are trying to understand what this sample does. This is just an experimental tool" ascii //weight: 10
        $x_1_2 = "Crypto.Cipher._EKSBlowfish" ascii //weight: 1
        $x_1_3 = "bCrypto\\Cipher\\_raw_aes.pyd" ascii //weight: 1
        $x_1_4 = "PYINSTALLER_STRICT_UNPACK_MODE" ascii //weight: 1
        $x_1_5 = "email._encoded_words" ascii //weight: 1
        $x_1_6 = "email._header_value_parser" ascii //weight: 1
        $x_1_7 = "email.message" ascii //weight: 1
        $x_1_8 = "bCrypto\\Protocol\\_scrypt.pyd" ascii //weight: 1
        $x_1_9 = "b_socket.pyd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


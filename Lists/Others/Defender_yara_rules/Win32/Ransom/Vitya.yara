rule Ransom_Win32_Vitya_YAUA_2147976389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Vitya.YAUA!MTB"
        threat_id = "2147976389"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Vitya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "After buying cryptocurrency from a broker, store the cryptocurrency on a cold wallet" ascii //weight: 4
        $x_4_2 = "Don't go to the police or the FBI for help and don't tell anyone that we attacked you" ascii //weight: 4
        $x_4_3 = "You can think of this paid decryption as a security test" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


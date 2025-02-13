rule Ransom_Win32_DeathRansom_ADT_2147920846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DeathRansom.ADT!MTB"
        threat_id = "2147920846"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DeathRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a c3 c0 e8 07 0f b6 c0 6b c8 1b 8a c3 02 c0 32 c8 32 d9 3a da}  //weight: 2, accuracy: High
        $x_1_2 = "DEATHRansom" ascii //weight: 1
        $x_1_3 = "Your files were encrypted" ascii //weight: 1
        $x_1_4 = "You have only 12 hours to decrypt it" ascii //weight: 1
        $x_1_5 = "In case of no answer our team will delete your decryption password" ascii //weight: 1
        $x_1_6 = "Write back to our e-mail: deathransom@airmail.cc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


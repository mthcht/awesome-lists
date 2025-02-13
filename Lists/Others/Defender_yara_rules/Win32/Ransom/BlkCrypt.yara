rule Ransom_Win32_BlkCrypt_SL_2147772043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlkCrypt.SL!MTB"
        threat_id = "2147772043"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlkCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Ransom_Note_Load>" ascii //weight: 1
        $x_1_2 = "Start_Encrypt" ascii //weight: 1
        $x_1_3 = "Success: Don't worry, I will decrypt your files in just a bit" ascii //weight: 1
        $x_1_4 = "You did not made a payment! Try again" ascii //weight: 1
        $x_1_5 = "pay for code: InstantRansom@gmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


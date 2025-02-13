rule Ransom_Win32_HwruGo_SV_2147767751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HwruGo.SV!MTB"
        threat_id = "2147767751"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HwruGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "We would share your SENSITIVE DATA in case you refuse to pay" ascii //weight: 1
        $x_1_2 = "ANY ATTEMPT TO RESTORE YOUR FILES WITH THIRD-PARTY SOFTWARE WILL PERMANENTLY CORRUPT IT" ascii //weight: 1
        $x_1_3 = "DO NOT MODIFY ENCRYPTED FILES" ascii //weight: 1
        $x_1_4 = "DO NOT RENAME ENCRYPTED FILES" ascii //weight: 1
        $x_1_5 = "But keep calm! There is a solution for your problem!" ascii //weight: 1
        $x_1_6 = "For some money reward we can decrypt all your encrypted files" ascii //weight: 1
        $x_1_7 = "Also we will delete all your private data from our servers" ascii //weight: 1
        $x_1_8 = "To prove that we are able to decrypt your files we give you the ability to decrypt 2 files for free" ascii //weight: 1
        $x_1_9 = "So what is you next step ? Contact us for price and get the decryption software" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}


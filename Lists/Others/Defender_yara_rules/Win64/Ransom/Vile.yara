rule Ransom_Win64_Vile_SAYR_2147971670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Vile.SAYR!MTB"
        threat_id = "2147971670"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Vile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "your computer is now under the control of the vile collective." ascii //weight: 2
        $x_1_2 = "All your files are have been encrypted with military-grade encryption." ascii //weight: 1
        $x_1_3 = "The encryption key has been sent to our secure server. Without it, your files cannot be recovered." ascii //weight: 1
        $x_1_4 = "Any attempt to modify, recover, or remove this application will result in the PERMANENT DESTRUCTION of your decryption key" ascii //weight: 1
        $x_1_5 = "Amount: $1,500 USD" ascii //weight: 1
        $x_1_6 = "If you attempt to power down, the decryption key will be destroyed" ascii //weight: 1
        $x_1_7 = "Provide your Victim ID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


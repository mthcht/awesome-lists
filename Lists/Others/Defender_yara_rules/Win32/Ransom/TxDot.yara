rule Ransom_Win32_TxDot_AB_2147766218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TxDot.AB!MTB"
        threat_id = "2147766218"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TxDot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Read this message CAREFULLY and contact someone from IT department." ascii //weight: 1
        $x_1_2 = "!TXDOT_READ_ME!.txt" ascii //weight: 1
        $x_1_3 = "Your files are securely ENCRYPTED" ascii //weight: 1
        $x_1_4 = "MODIFICATION or RENAMING encrypted files may cause decryption failure" ascii //weight: 1
        $x_1_5 = "so you have no doubts in possibility to restore all files from all affected systems ANY TIME" ascii //weight: 1
        $x_1_6 = "The rest of data will be available after the PAYMENT" ascii //weight: 1
        $x_1_7 = "Contact us ONLY if you officially represent the whole affected network" ascii //weight: 1
        $x_1_8 = "The PRICE depends on how quickly you do it" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


rule Trojan_Win32_PersianRat_APR_2147896741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PersianRat.APR!MTB"
        threat_id = "2147896741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PersianRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Persian" wide //weight: 1
        $x_1_2 = "DH_TinyKeylogger" ascii //weight: 1
        $x_1_3 = "QMany of your documents, photos, videos , databases and other files are no longer" ascii //weight: 1
        $x_1_4 = "KAccesible Because They Have Been Encrypted. Maybe You Are Busy Looking For" ascii //weight: 1
        $x_1_5 = "YA Way To Recover Your Files, But Do Not Waste Your Time, Nobody Can Recover Files Without" ascii //weight: 1
        $x_1_6 = "7if you want to decrypt all your files, you need to pay" ascii //weight: 1
        $x_1_7 = "TYou Cannnot Decrypt your files for free. after payment try now by clicking" ascii //weight: 1
        $x_1_8 = "YYou Only Have 3 Days to Submit the payment. After that this window will be closed forever" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


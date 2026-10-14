rule Trojan_MSIL_Obfuscated_JN_2147980303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Obfuscated.JN!MTB"
        threat_id = "2147980303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Obfuscated"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_2_2 = "rfsTW_LorNnacV5TTwdZ50Iqx08TqQAyynCwhTkAQX50VPLQQxFTNI7OX9UGmlUNsjfjqa0lF9hXoGZXV9y" ascii //weight: 2
        $x_1_3 = "QI28CykM59KOstnL1BrBYi_99njOePwBKkOb0u8QD96dEn2bX7x13zX9vb9uk6oeLMGnWz1T_rB6YPBKVj0WIyF7HNU16sR" ascii //weight: 1
        $x_1_4 = "eZLqb3eVkEW6UftbQ8KwH0dOK4SSXsj0b_BlqomAZEUdcZikt5YxKXPwwASwy0elb9pMxR" ascii //weight: 1
        $x_1_5 = "lRQbgO75vAVkNVjtZY06zKZr0Y85GvPPKKCsfVDnOFg6CMgWmzpb7lfrSgGQBzKWPjplD7Zir4nu7mQXb" ascii //weight: 1
        $x_1_6 = "WebResponse" ascii //weight: 1
        $x_1_7 = "set_UseShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


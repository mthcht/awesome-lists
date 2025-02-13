rule Trojan_Win32_CrypMIC_AMAX_2147917215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrypMIC.AMAX!MTB"
        threat_id = "2147917215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrypMIC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ALL YOUR FILES were encrypted with the public key, which has been transferred to your computer via the Internet." ascii //weight: 2
        $x_1_2 = "Decrypting of your files is only possible with the help of the private key and decrypt program , which is on our Secret Server" ascii //weight: 1
        $x_1_3 = "If You have really valuable _DATA_, you better _NOT_ _WASTE_ _YOUR_ _TIME_, because there is _NO_ other way to get your files, except make a _PAYMENT_" ascii //weight: 1
        $x_1_4 = ":\\TEMP\\README.TXT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


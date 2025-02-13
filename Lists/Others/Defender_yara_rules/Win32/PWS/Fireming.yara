rule PWS_Win32_Fireming_A_2147595828_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fireming.A"
        threat_id = "2147595828"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fireming"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Content-Disposition: form-data; name=\"userfile\"; filename=\"%s\"" ascii //weight: 1
        $x_1_2 = "%s\\hlst.tmp" ascii //weight: 1
        $x_1_3 = "multiscshs" ascii //weight: 1
        $x_1_4 = "%s\\dllcache\\%s" ascii //weight: 1
        $x_1_5 = "%suserinit.exe," ascii //weight: 1
        $x_1_6 = "%sautorun.inf" ascii //weight: 1
        $x_1_7 = "%s__PS.txt" ascii //weight: 1
        $x_1_8 = "Windows Server 2003" ascii //weight: 1
        $x_1_9 = ".htm*.php*.do*.asp*.jsp*?" ascii //weight: 1
        $x_1_10 = "%s%s%s&cnt=%s&hp=%d&sp=%d" ascii //weight: 1
        $x_1_11 = "172.16." ascii //weight: 1
        $x_1_12 = "SOCK_SEQPACKET" ascii //weight: 1
        $x_1_13 = {00 70 73 74 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_14 = "ebay.co.uk" ascii //weight: 1
        $x_1_15 = "amazon.co.uk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule PWS_Win32_Fireming_A_2147595828_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fireming.A"
        threat_id = "2147595828"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fireming"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d c8 00 00 00 0f 85 ?? ?? 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 10 02 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 02 00 00 00 c7 44 24 04 00 00 00 40 [0-6] 89 04 24 e8}  //weight: 2, accuracy: Low
        $x_1_2 = "%s?user=%s&mod=log" ascii //weight: 1
        $x_1_3 = "%s?mod=log&user=%s" ascii //weight: 1
        $x_1_4 = "http://%s:%i%s?mod=cmd" ascii //weight: 1
        $x_1_5 = "<b>PostData: </b>%s<br>" ascii //weight: 1
        $x_1_6 = "Software\\YHelper" ascii //weight: 1
        $x_1_7 = "Mozilla/5.0 Gecko/20050212 Firefox/1.5.0.2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


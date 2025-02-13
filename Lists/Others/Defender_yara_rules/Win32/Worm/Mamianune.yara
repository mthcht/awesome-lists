rule Worm_Win32_Mamianune_2147584583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mamianune"
        threat_id = "2147584583"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mamianune"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mamianunennolaelleiaorardadodeueta q sammees a p cralore yo era u e tionetalab tMApiSyumofintenepeceseduegnithpobococaadirtrsacrmuuiemassoisgoront hmo<h<t></t/f/hmlri()=\"e=urogaiirccli{ }<_leyxAckct32" ascii //weight: 10
        $x_1_2 = "Content-Type: multipart/mixed; boundary=" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "mail from:<" ascii //weight: 1
        $x_1_5 = "rcpt to:<" ascii //weight: 1
        $x_1_6 = "Content-Transfer-Encoding: base64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}


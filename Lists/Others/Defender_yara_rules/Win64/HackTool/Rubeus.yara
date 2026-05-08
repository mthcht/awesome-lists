rule HackTool_Win64_Rubeus_VGL_2147968802_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Rubeus.VGL!MTB"
        threat_id = "2147968802"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rubeus"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LamatopyImpedIntricArmate.Kerberos.PAC" ascii //weight: 1
        $x_1_2 = "sha1WithRSAEncryption_CmsOI" ascii //weight: 1
        $x_1_3 = "md5WithRSAEncryption_CmsOID" ascii //weight: 1
        $x_1_4 = "DONT_EXPIRE_PASSWORD" ascii //weight: 1
        $x_1_5 = "PASSWD_CANT_CHANGE" ascii //weight: 1
        $x_1_6 = "KERB_RETRIEVE_TICKET_DONT_USE_CACHE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


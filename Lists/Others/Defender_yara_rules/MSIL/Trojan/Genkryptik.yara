rule Trojan_MSIL_GenKryptik_ELPQ_2147758231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GenKryptik.ELPQ!MTB"
        threat_id = "2147758231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GenKryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NJSDKLDHSD" ascii //weight: 1
        $x_1_2 = "$cd734b90-2f70-4f7d-84bc-cda322f2eb17" ascii //weight: 1
        $x_1_3 = "RijndaelManaged" ascii //weight: 1
        $x_1_4 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_5 = "DaoVangClient" ascii //weight: 1
        $x_1_6 = "PbPlayerKeyUp" ascii //weight: 1
        $x_1_7 = "PbPlayerKeyDown" ascii //weight: 1
        $x_1_8 = "gra1.FormGame.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


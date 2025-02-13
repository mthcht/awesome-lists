rule VirTool_O97M_Empire_A_2147779288_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:O97M/Empire.A"
        threat_id = "2147779288"
        type = "VirTool"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SysTeM.XML.XmLDOcUMEnt" ascii //weight: 1
        $x_1_2 = ".LOAD('http" ascii //weight: 1
        $x_1_3 = "::UTF8.geTByTEs(" ascii //weight: 1
        $x_1_4 = "::FROMBase64StrinG(" ascii //weight: 1
        $x_1_5 = "SecURity.CRYptOGRApHy.AEsManageD" ascii //weight: 1
        $x_1_6 = "().TRANSFoRMFINaLBLoCk(" ascii //weight: 1
        $x_1_7 = "|iEX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_O97M_Empire_E_2147812181_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:O97M/Empire.E!MTB"
        threat_id = "2147812181"
        type = "VirTool"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Empire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "exec(base64.b64decode('" ascii //weight: 1
        $x_1_2 = "python" ascii //weight: 1
        $x_1_3 = "winmgmts:\\\\.\\root\\cimv2" ascii //weight: 1
        $x_1_4 = {2e 53 68 6f 77 57 69 6e 64 6f 77 [0-5] 3d [0-5] 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


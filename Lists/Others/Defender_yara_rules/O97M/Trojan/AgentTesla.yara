rule Trojan_O97M_AgentTesla_ASMQ_2147832340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/AgentTesla.ASMQ!MTB"
        threat_id = "2147832340"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "~~$$ppd$$t$$~~ro$$ming~~microsoft~~windows~~st$$rtmenu~~progr$$ms~~st$$rtup~~upd$$te!!\"" ascii //weight: 1
        $x_1_2 = ":::::=vba.replace(,\"~~\",\"\\\\\"):::::=vba.replace(,\"!!\",\".js\"):::::=vba.replace(,\"$$\",\"a\")=\"@@~~users~~public~~sys.ini\":::::=vba.replace(,\"~~\",\"\\\"):::::=vba.replace(,\"@@\",\"c:\")" ascii //weight: 1
        $x_1_3 = "@@//b//e:~~c:&users&public&sys.ini\"" ascii //weight: 1
        $x_1_4 = ":::::=vba.replace(,\"&\",\"\\\\\"):::::=vba.replace(,\"@@\",\"wscript.exe\"):::::=vba.replace(,\"~~\",\"jscript\")debug.print:::::set=getobject(\"new:{72c24dd5-d70a-438b-8a42-98424b88afb8}\")debug.print:::::::set=_.__exec!()debug.printendfunction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Reccoon_A_2147757059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reccoon.A"
        threat_id = "2147757059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reccoon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QWevuxepigekik yeman xogosikijak jewalus zuxasozoticim tosof buyadiboba setokaripa" wide //weight: 1
        $x_1_2 = "Kagomoritumi7Cevocemezo sap nivavub gedusuxiso malom kewigikuputusip" wide //weight: 1
        $x_1_3 = "JilidixecGWukokicofo ziha luxu makijidesecadux buj baf comegazafefapir remo zolenAKeguroziwi yifipiriwiyup" wide //weight: 1
        $x_1_4 = "GekogNit baxuvunuyud yomesidexi gozatiratezejul gafuzopa nowuto wofopidozudonor dipap fuzalulu medotetirocib" wide //weight: 1
        $x_1_5 = "Liwufepojotapax paru teveyurehe yanilugovu xeyayer lohagagulove" wide //weight: 1
        $x_1_6 = "Visocuhu kuzufuwixoXJugemojoveto gerepeveripu zeyuwu xoxegazor navacujexudef duvexiguranunef bisakelunafuhiy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


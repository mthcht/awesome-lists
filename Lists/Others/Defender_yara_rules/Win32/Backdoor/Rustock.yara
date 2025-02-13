rule Backdoor_Win32_Rustock_E_2147792229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rustock.E"
        threat_id = "2147792229"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rustock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 f4 a2 a9 00 00 81 7d f4 bb 00 00 00 7f 20 c7 45 ec 65 2f 00 00 c7 45 f8 56 41 08 f7}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 11 81 fa 4d 5a 00 00 74 5f 8b 45 f8 2d 00 10 00 00 89 45 f8 c7 45 e8 47 00 00 00 c7 45 f0 80 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rustock_2147792408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rustock"
        threat_id = "2147792408"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rustock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "abgc\\tf\\jl\\yijuq\\muztf\\xoaxl\\kqtnowscvoh.pdb" ascii //weight: 1
        $x_1_2 = "apj\\upxbx\\jdqlelx\\ecrlct\\wddkhiq\\chgrgeyu.pdb" ascii //weight: 1
        $x_1_3 = "autvj\\gyhurh\\vlzk\\jvf\\pjpqtp\\scbtq\\pagtvck.pdb" ascii //weight: 1
        $x_1_4 = "bbtjlqlus\\ptdhaea\\baydfsdm\\zhjygpwymfyqpk.pdb" ascii //weight: 1
        $x_1_5 = "bmufrizyncinh\\zyowttwfer\\iihvtiahwe.pdb" ascii //weight: 1
        $x_1_6 = "ccvyoewsj\\ablqgegywtligujlc\\saduqaki.pdb" ascii //weight: 1
        $x_1_7 = "coxux\\skqcsf\\zoqtr\\pjkteap\\pqcgvcm\\mmmhlb.pdb" ascii //weight: 1
        $x_1_8 = "dkdgbzh\\gcuhwkanheso\\ywngeslyxgwieszxl.pdb" ascii //weight: 1
        $x_1_9 = "dsbu\\rhnxwu\\eyoqtq\\yrpl\\dahutmat\\mnyofbrkexi.pdb" ascii //weight: 1
        $x_1_10 = "dufji\\paai\\pzaiuq\\lfitc\\qbznu\\tyxovdo\\kota.pdb" ascii //weight: 1
        $x_1_11 = "edfex\\krco\\gcy\\kfbruv\\zcdajl\\achjvafk.pdb" ascii //weight: 1
        $x_1_12 = "eje\\zk\\avxejid\\airj\\qnpbqk\\ycmb\\iyfnyyyjuhni.pdb" ascii //weight: 1
        $x_1_13 = "fhdbowtuv\\vmvsianxitnny\\vdicmfnjmyoyphr.pdb" ascii //weight: 1
        $x_1_14 = "fiicc\\yxxp\\hzjcqcui\\gkkctwba\\eafxjkiaowgh.pdb" ascii //weight: 1
        $x_1_15 = "fpo\\oblmtfi\\kedc\\pvbe\\zytgwfer\\bsadjx.pdb" ascii //weight: 1
        $x_1_16 = "gmegy\\rfhdvednqkbejhw\\tinvyfunzzcmtedvnzb.pdb" ascii //weight: 1
        $x_1_17 = "gwkm\\uf\\qltaip\\fudbo\\pdhz\\kjbvodm\\muhqxj.pdb" ascii //weight: 1
        $x_1_18 = "hcheftu\\zdisi\\jnqnh\\eewueyk\\frsampap\\pfrbvwpk.pdb" ascii //weight: 1
        $x_1_19 = "htny\\uefck\\vnto\\nnom\\jipx\\luwpjig\\sxdyycwmfl.pdb" ascii //weight: 1
        $x_1_20 = "ihisy\\kft\\kwvp\\zplng\\afhnltxc\\xdhw\\aabmcuoyp.pdb" ascii //weight: 1
        $x_1_21 = "ijsv\\degkgbtotstwr\\yzckxymdibovz\\rxrwreq.pdb" ascii //weight: 1
        $x_1_22 = "jiesgkr\\hzg\\frhdkgf\\fyqdvwnbh\\ukrtxscmzr.pdb" ascii //weight: 1
        $x_1_23 = "kpm\\vfwep\\whwxkjl\\wixzyx\\zxnv\\skmpk\\idikzhw.pdb" ascii //weight: 1
        $x_1_24 = "kxobipjxypwehro\\zhylzpodauc\\lnbugoquozup.pdb" ascii //weight: 1
        $x_1_25 = "lchp\\uwzzuhv\\ybrlshvk\\eugf\\aijselsptahejy.pdb" ascii //weight: 1
        $x_1_26 = "lkgvr\\dzt\\wpfms\\ate\\soaadn\\ufabtajgu\\wxvv.pdb" ascii //weight: 1
        $x_1_27 = "mytjkb\\eoios\\cit\\wgr\\hymysze\\uqiiges\\drxomxv.pdb" ascii //weight: 1
        $x_1_28 = "nblsyyxu\\zfftmgddaw\\dizsfgoacietju.pdb" ascii //weight: 1
        $x_1_29 = "nosyzuz\\oejk\\mtrscduina\\arlsz\\yfmulopmudlisq.pdb" ascii //weight: 1
        $x_1_30 = "npl\\kqq\\mhc\\crftart\\ywufww\\gcb\\axzytvrxzi.pdb" ascii //weight: 1
        $x_1_31 = "nro\\bcxho\\bmrhww\\qwcgahsk\\dobvuox\\pibpchd.pdb" ascii //weight: 1
        $x_1_32 = "nurmndcqwd\\zcqzsswi\\gonlvrpze\\otorjf.pdb" ascii //weight: 1
        $x_1_33 = "obpg\\qjjr\\gedu\\twqovibyk\\gbvtkxh\\biigdfx.pdb" ascii //weight: 1
        $x_1_34 = "qnymvd\\iil\\hbfv\\ifhwtk\\lbxzzdog\\txaeelclmwodd.pdb" ascii //weight: 1
        $x_1_35 = "qt\\zgulv\\layrs\\abe\\fudimzpsm\\ghyhwnmk\\ngjn.pdb" ascii //weight: 1
        $x_1_36 = "rtzoxopwmu\\stgcwj\\meauc\\mfmwlfxcvaotcyfjcxf.pdb" ascii //weight: 1
        $x_1_37 = "rxk\\zphfk\\znavk\\jolt\\sesw\\okdzg\\xlymzrya.pdb" ascii //weight: 1
        $x_1_38 = "ssatxzdhxli\\goigxggiu\\gzdrlfhpblofakqkf.pdb" ascii //weight: 1
        $x_1_39 = "szhx\\ebnih\\thlj\\aiuwq\\jrkumyo\\zmdwokxnfqyi.pdb" ascii //weight: 1
        $x_1_40 = "vafn\\hewwyx\\opfsibsev\\nbvvzplhc\\upqiclutq.pdb" ascii //weight: 1
        $x_1_41 = "wcppa\\jvp\\tmqsqudhv\\vcqrmhyv\\sodhqg\\fyeuk.pdb" ascii //weight: 1
        $x_1_42 = "wpvjotbil\\gmmnc\\abvfwp\\xrzikstx\\qpozziqzcl.pdb" ascii //weight: 1
        $x_1_43 = "xjjhkuth\\cwwagyur\\xrhqzebkvvly.pdb" ascii //weight: 1
        $x_1_44 = "ycfukexcmj\\fjhmqau\\jtkpwfedyhibl\\ontcrwhaqng.pdb" ascii //weight: 1
        $x_1_45 = "yrjnuf\\dmif\\mhpoxrm\\cuvmd\\tumxgi\\zaskjut.pdb" ascii //weight: 1
        $x_1_46 = "hkfp\\huwwhyye\\faqhnb\\lrymrk\\kcuvlmhl\\qdkhgcg.pdb" ascii //weight: 1
        $x_1_47 = "riovk\\pnmrfj\\ouevl\\sosqjisg\\rjm\\goqpcgtjvda.pdb" ascii //weight: 1
        $x_1_48 = "alqvmvy\\obbd\\ulqwuw\\twqwuuyygpt\\fgftcklbl.pdb" ascii //weight: 1
        $x_1_49 = "aavmursarpsu\\nayxntbpj\\kdlusrfmjtyiww.pdb" ascii //weight: 1
        $x_1_50 = "nmfaxb\\jorivyisfp\\ucoimlpcpjoxjxscvbb.pdb" ascii //weight: 1
        $x_1_51 = "otccgjg\\qkfszklqt\\wkrit\\qdtjiynefammqejvermi.pdb" ascii //weight: 1
        $x_1_52 = "xnhqf\\umrtvimevt\\xfumiunq\\omusreoi.pdb" ascii //weight: 1
        $x_1_53 = "ihlnqc\\nwdh\\kmqru\\czkg\\fqxbfap\\jiwf\\epals.pdb" ascii //weight: 1
        $x_1_54 = "aixyhj\\aouylphpdole\\yjskmoeehf\\vxygaupxq.pdb" ascii //weight: 1
        $x_1_55 = "skwosa\\phli\\bbzn\\zgooqdlyv\\afuuvo\\qlubqx.pdb" ascii //weight: 1
        $x_1_56 = "wft\\ppzezya\\oa\\uyqu\\cbhtje\\pbtaatsw\\txixqqc.pdb" ascii //weight: 1
        $x_1_57 = "kzadz\\hmffzvkhh\\tnahot\\cngxcslodw.pdb" ascii //weight: 1
        $x_1_58 = "dhewgn\\wetnuv\\wiaamdcm\\vtkjubfvo\\ktboj.pdb" ascii //weight: 1
        $x_1_59 = "pguzcct\\hmnybifgzormgrzfwcu\\koypgqvwfyapasami.pdb" ascii //weight: 1
        $x_1_60 = "vcpyly\\uzzy\\bsnepa\\pwdtrfsuq\\apclurh.pdb" ascii //weight: 1
        $x_1_61 = "zmlztnintwea\\rolyppdztnbql\\cxdemrglxrkwqfm.pdb" ascii //weight: 1
        $x_1_62 = "xdyy\\axkaxpwb\\siuxpjhvdjycgx\\iqwzjgxsoje.pdb" ascii //weight: 1
        $x_1_63 = "jmk\\gzwnl\\mrxsdm\\pvmaesd\\rkqvtnn\\tkcti\\kwla.pdb" ascii //weight: 1
        $x_1_64 = "kergxusilx\\nhlzwhz\\zcyhif\\qedzqekxxohfw.pdb" ascii //weight: 1
        $x_1_65 = "wcd\\oxnw\\rvaghva\\qzhcb\\sqpiuuio\\uhbcwo.pdb" ascii //weight: 1
        $x_1_66 = "cwb\\nrjufvtq\\suxj\\zjgvyaivowr\\zxnyuyttyvglbj.pdb" ascii //weight: 1
        $x_1_67 = "zcvilz\\oem\\fpadgoo\\sfnjj\\rdvuk\\ahzcpspbow.pdb" ascii //weight: 1
        $x_1_68 = "demb\\zrdls\\naxcleze\\jokiltgn\\ucdzovswgtj.pdb" ascii //weight: 1
        $x_1_69 = "ldcsgmcelz\\jzirewafezcxq\\ycxqfxmphkyymkf.pdb" ascii //weight: 1
        $x_1_70 = "rd\\hruje\\jes\\heycgrj\\vjpvx\\lyvf\\ymmzm.pdb" ascii //weight: 1
        $x_1_71 = "osqji\\peqhtwmj\\woxhehnyid\\mhavoutwcwsgivlqsd.pdb" ascii //weight: 1
        $x_1_72 = "eczkqw\\vdj\\nuzbsnr\\hydz\\ezoqa\\bszxtdf\\pazcx.pdb" ascii //weight: 1
        $x_1_73 = "bigytow\\rzggawqopxm\\dioffgggikzqjyse.pdb" ascii //weight: 1
        $x_1_74 = "wcbobzeoz\\irljstrx\\xwrboorojcx.pdb" ascii //weight: 1
        $x_1_75 = "tror\\ro\\tjne\\ltxquby\\xqoezs\\rupoamx\\tzghie.pdb" ascii //weight: 1
        $x_1_76 = "kvxvcpox\\nhzjhdhcqtvo\\quusgdbhbxzssbluvkxh.pdb" ascii //weight: 1
        $x_1_77 = "pgoxg\\dqjj\\afgyfgr\\rnefg\\vavmwik\\jn\\dsbmzdd.pdb" ascii //weight: 1
        $x_1_78 = "ftmubg\\avgusf\\pismnh\\ooykz\\oqqmvyolrqerlq.pdb" ascii //weight: 1
        $x_1_79 = "ot\\oov\\aqfuk\\kqbib\\eizwf\\iuwgpcsxjx\\oxmdae.pdb" ascii //weight: 1
        $x_1_80 = "mhvacqipq\\czfrdcmysfb\\sqzhfamdcv\\wxxdqpgjlm.pdb" ascii //weight: 1
        $x_1_81 = "uacui\\pooygnpdlu\\zfuwxqycqlu.pdb" ascii //weight: 1
        $x_1_82 = "wtnnpg\\cu\\qwt\\epmrdvs\\gmjfp\\usmaebgfjdqqaeb.pdb" ascii //weight: 1
        $x_1_83 = "gngkr\\jdwiroaza\\bwtnjtjo\\akcqclqv\\duozxi.pdb" ascii //weight: 1
        $x_1_84 = "dfv\\bqfi\\amndg\\vdbrx\\fsuwdrvxom\\upuxjnie.pdb" ascii //weight: 1
        $x_1_85 = "ahwacdu\\dxfddkg\\grghjqel\\nxwvptswlaigndw.pdb" ascii //weight: 1
        $x_1_86 = "zdinecfpju\\fjyjwo\\rrrchrpwqnantrubcmbpawe.pdb" ascii //weight: 1
        $x_1_87 = "xcjezrp\\mctzvxt\\cqepac\\gplpalat\\xwspasuqvvzf.pdb" ascii //weight: 1
        $x_1_88 = "aolhjn\\eeiskqswku\\oyuretpjweo\\vhwoyjoykbxfob.pdb" ascii //weight: 1
        $x_1_89 = "vnrb\\uptg\\hyjbykvlq\\hwwkbnsenstqdzngftyj.pdb" ascii //weight: 1
        $x_1_90 = "phfhq\\bpzpz\\rgvoruzukkucswxi\\rqspbvie.pdb" ascii //weight: 1
        $x_1_91 = "apvy\\udzgimu\\yuopi\\fckxx\\eiajlydwx\\ryzpzr.pdb" ascii //weight: 1
        $x_1_92 = "chliml\\jvsmypzyqmpm\\ssegzxmuybxsg.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


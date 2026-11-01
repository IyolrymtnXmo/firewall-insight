// English page copy lives in index.html (the default language).
// Edit the Thai translations, feature screens and demo data here.
// Every key below matches a data-i18n attribute in index.html.
// The page stays buildless and works from both HTTP and file:// previews.
window.FirewallInsightContent = (() => {
const thai = {
  skip: "ข้ามไปยังเนื้อหา",
  navOverview: "ภาพรวม",
  navCapabilities: "ความสามารถ",
  navExplore: "หน้าจอจริง",
  navResearch: "ผลวิจัย",
  navWorkflow: "วิธีทำงาน",
  navSource: "Source Code",
  heroEyebrow: "CHECK POINT POLICY INTELLIGENCE",
  heroTitleOne: "มองเห็นทุกกฎ",
  heroTitleTwo: "เข้าใจทุกความเสี่ยง",
  heroDescription: "เปลี่ยนข้อมูลไฟร์วอลล์ที่ซับซ้อนให้เป็นภาพรวมที่อ่านง่าย สำรวจ Policy, เส้นทางทราฟฟิก และหลักฐานการตรวจสอบในพื้นที่ทำงานเดียว",
  heroDemo: "ลองใช้เดโมจริง",
  heroExplore: "สำรวจความสามารถ",
  heroGithub: "ดูบน GitHub",
  heroProof: "Read-only by design · ไม่มีการแก้ไข Policy บน Check Point",
  stageTab1: "สุขภาพ Policy",
  stageTab2: "เส้นทางทราฟฟิก",
  stageTab3: "ไม่ทราบ ≠ ไม่ตรง",
  stageTab4: "แผนที่เครือข่าย",
  chipHeuristic: "คะแนนคำนวณในแอป ไม่ใช่คะแนนของ Check Point",
  chipNoPacket: "จำลองจากการตั้งค่า ไม่ส่งแพ็กเก็ตจริง",
  chipAsk: "ถามเป็นภาษาไทยได้",
  chipUnknownNote: "บอกว่าไม่ทราบ ดีกว่าตอบผิดอย่างมั่นใจ",
  chipMembership: "ไม่เดาสมาชิกคลัสเตอร์จาก IP",
  stageCaption: "ข้อมูลในการ์ดถอดจากหน้าจอจริงและโปสเตอร์ของโปรเจกต์ (แล็บ External-FW · 15 ต.ค. 2026) แผนผังเครือข่ายเป็นแบบย่อ",
  stackCaption: "สร้างบน API และเครื่องมือที่ใช้งานจริง",
  overviewKicker: "WHY IT MATTERS",
  overviewTitle: "Policy ที่มองเห็น<br><em>คือการตัดสินใจที่มั่นใจขึ้น</em>",
  overviewIntro: "เมื่อ Rulebase, Topology และผลการตรวจสอบอยู่คนละที่ การตอบคำถามง่าย ๆ ก็ใช้เวลานาน Firewall Insight รวบรวมบริบทที่จำเป็นไว้ให้สำรวจได้ต่อเนื่อง",
  originLabel: "โจทย์ตั้งต้น",
  overviewOrigin: "เริ่มจากงานจริงของทีม Infrastructure Security: ย้ายนโยบายเดิมราว 600 และ 300 กฎไปยังคลัสเตอร์ Check Point โดยยังไม่รู้ว่ากฎใดซ้ำซ้อนหรือถูกบดบัง และเครื่องมือที่ใช้ต้องไม่แก้ไขระบบของลูกค้า",
  overviewCard1Title: "อ่าน Rulebase ให้ชัด",
  overviewCard1Body: "เห็น Access และ NAT Policy ตามข้อมูลจริง พร้อมบริบทของ Inline Layer และจุดที่ควรกลับไปตรวจทาน",
  overviewCard2Title: "เชื่อมกฎกับทราฟฟิก",
  overviewCard2Body: "จำลองเส้นทางจากต้นทาง ปลายทาง และบริการ เพื่อดู Rule ที่อาจตรงกันพร้อมระดับความมั่นใจของผล",
  overviewCard3Title: "เก็บหลักฐานการเปลี่ยนแปลง",
  overviewCard3Body: "เทียบ Snapshot, ตรวจ Compliance และย้อนดู Review เพื่อสนับสนุนการตัดสินใจด้วยข้อมูลที่ตรวจสอบได้",
  capabilitiesKicker: "ONE CONNECTED VIEW",
  capabilitiesTitle: "จาก Rule หนึ่งบรรทัด<br>สู่ <em>ภาพรวมทั้งระบบ</em>",
  capabilitiesIntro: "เครื่องมือแต่ละส่วนเชื่อมคำถามด้านนโยบาย ความเสี่ยง และเครือข่ายเข้าด้วยกัน เลือกเจาะลึกเฉพาะสิ่งที่ทีมต้องการรู้",
  demoBadge: "ข้อมูลตัวอย่าง",
  capability1: "พบกฎที่ซ้ำ ซ้อนทับ หรือกว้างเกินไป",
  bentoFeedBody: "แยกการวิเคราะห์ตาม Layer กฎใน Inline Layer ต่างกันจะไม่ถูกเทียบกันเอง และ Unused เป็นแค่รายการให้ทบทวน ไม่ใช่คำสั่งลบ",
  guardNext: "ลองคำสั่งถัดไป",
  bentoGuardTitle: "ไม่มีคำสั่งเขียนแม้แต่บรรทัดเดียว",
  bentoGuardBody: "ใช้เฉพาะคำสั่งอ่านผ่าน Management API ชุดทดสอบจะล้มทันทีถ้ามีคำสั่ง add, set, delete, publish หรือ install-policy โผล่ในโค้ด",
  bentoStateTitle: "ตอบได้สามแบบ: ตรง ไม่ตรง และไม่ทราบ",
  bentoStateBody: "ใช้ตรรกะสามค่าของ Kleene กับ Inline Layer และ Implied Rule เมื่อเงื่อนไขใดประเมินจากการตั้งค่าไม่ได้ เครื่องมือจะบอกว่าไม่ทราบแทนการเดา",
  askReplay: "พิมพ์อีกครั้ง",
  bentoAskTitle: "ถามเป็นภาษาไทยก็เข้าใจ",
  bentoAskBody: "ตัวแยกคำแบบกำหนดผลได้ ไม่ใช้โมเดลภาษา และคำถามไม่ออกนอกแอป ถ้าข้อมูลไม่พอจะถามกลับแทนการเดา",
  capability4: "รวบรวมผล Review และขอบเขตที่อ่านไม่ได้",
  bentoReviewBody: "รีวิวหนึ่งครั้งรวมผลวิเคราะห์ ความเปลี่ยนแปลง Compliance และสุขภาพเกตเวย์ ส่วนที่อ่านไม่ได้ถูกบันทึกว่า “ไม่ได้อ่าน” ไม่ใช่ผลว่าง",
  capability3: "เปรียบเทียบการเปลี่ยนแปลงข้าม Snapshot",
  bentoDiffBody: "จับคู่กฎด้วย uid ไม่ใช่เลขลำดับ การแทรกกฎหนึ่งข้อจึงไม่ทำให้กฎข้างล่างทั้งหมดถูกนับว่าเปลี่ยน และกฎที่เทียบไม่ได้จะแยกเป็นหมวดของตัวเอง",
  modulesLabel: "14 หน้าในแอปเดียว",
  exploreKicker: "SEE IT IN ACTION",
  exploreTitle: "ไม่ต้องจินตนาการ<br><em>นี่คือหน้าจอจริง</em>",
  exploreIntro: "เลือกดูส่วนต่าง ๆ ของ Firewall Insight จากภาพที่บันทึกไว้ในโปรเจกต์ ภาพเหล่านี้เป็นตัวอย่างของ UI และข้อมูล ณ เวลาที่จับภาพ",
  tabAnalysis: "Policy Analysis",
  tabPath: "Traffic Path",
  tabMap: "Network Map",
  tabDiff: "Policy Diff",
  tabCompliance: "Compliance",
  tabHealth: "Gateway Health",
  tabUsage: "Rule Usage",
  tabTrends: "Trends",
  featureMore: "อ่านรายละเอียดฟีเจอร์",
  captureLabel: "PRODUCT CAPTURE",
  researchKicker: "RESEARCH · NCCY 2026",
  researchTitle: "ตอบให้ถูก<br><em>หรือบอกตรง ๆ ว่าไม่ทราบ</em>",
  researchIntro: "Firewall Insight ถูกประเมินกับข้อมูลที่รู้คำตอบล่วงหน้า ทั้งนโยบายสังเคราะห์และเกตเวย์จริงในแล็บ เป้าหมายไม่ใช่ตอบได้ทุกคำถาม แต่คือไม่ตอบผิดแบบมั่นใจ",
  stat1: "กฎสังเคราะห์ที่รู้คำตอบ",
  stat2: "การเชื่อมต่อจำลอง",
  stat3: "ผลยืนยันที่ผิด หลังแก้ข้อบกพร่อง 4 จุด",
  stat4: "ผลยืนยันตรงกับเกตเวย์จริง",
  chart1Title: "ครอบคลุมกฎที่ไม่มีวันถูกใช้",
  chart1Sub: "7,050 กฎที่รู้คำตอบ · 730 กฎที่ไม่มีวันถูกใช้",
  chart1Pair: "ตรวจแบบคู่กฎ",
  chart1Multi: "คู่ + หลายกฎ",
  chart1Note: "Recall เทียบกฎที่ไม่ถูกใช้ทั้งหมด · ไม่มีการรายงานผิดทั้งสองแบบ",
  chart2Title: "ต่อ 100 คำถาม",
  chart2Sub: "เทียบแบบจำลองเกตเวย์ 36,000 การเชื่อมต่อ · เลือกสัดส่วนเงื่อนไขที่ไม่ทราบ",
  chart2Two: "สองสถานะ: ตอบผิด",
  chart2Three: "สามสถานะ: ตอบยืนยัน (ผิด 0)",
  chart3Title: "เทียบกับเกตเวย์จริง",
  chart3Sub: "22 กรณีบนนโยบายชั้นนอก 16 กฎ",
  tile1: "ตรงกับ fw up_execute · อีก 7 กรณีงดตอบแทนการเดา",
  tile2: "คำสั่งเขียนถูกปฏิเสธ (บัญชี Read Only All)",
  tile3: "Log จริงระบุกฎตรงกัน",
  tile4: "ข้อบกพร่องที่พบและแก้แล้ว",
  paperTitle: "กรอบงานตรวจสอบนโยบายไฟร์วอลล์แบบอ่านอย่างเดียวที่คำนึงถึงความไม่แน่นอนของการประเมินกฎ",
  paperSub: "An Uncertainty-Aware Read-Only Framework for Firewall Policy Verification",
  paperVenue: "บทความเทคนิคสหกิจศึกษา ณ บริษัท เนตโปเลียน (ประเทศไทย) · มหาวิทยาลัยขอนแก่น",
  researchNote: "ตัวเลขจากบทความฉบับ v12 นโยบายที่ใช้ทดสอบเขียนขึ้นเองทั้งหมด ไม่ใช่ข้อมูลลูกค้า",
  workflowKicker: "FROM DATA TO DECISION",
  workflowTitle: "ข้อมูลที่อ่านได้<br><em>นำไปสู่การลงมือที่แม่นขึ้น</em>",
  workflowIntro: "วางการสำรวจนโยบายให้อยู่ในลำดับที่เข้าใจง่าย ตั้งแต่การอ่านข้อมูล ไปจนถึงการทบทวนผล โดยยังให้คนเป็นผู้ตัดสินใจเสมอ",
  workflow1Title: "Connect &amp; read",
  workflow1Body: "ดึงข้อมูลผ่าน Check Point Management API ด้วยสิทธิ์อ่าน และเชื่อม Gaia API เมื่อเปิดใช้สำหรับข้อมูล Gateway",
  workflow2Title: "Explore &amp; explain",
  workflow2Body: "สำรวจ Rule, Topology, Traffic Path และจุดที่ควรตรวจทานจากบริบทเดียวกัน",
  workflow3Title: "Review &amp; compare",
  workflow3Body: "เทียบ Snapshot, ตรวจตาม Profile ที่เลือก และเก็บประวัติ Review เพื่อย้อนดูภายหลัง",
  workflowExplore: "สำรวจแพลตฟอร์ม",
  navDemo: "เดโมแบบโต้ตอบ",
  exploreDemo: "ลองใช้เดโมแบบโต้ตอบ",
  exploreDemoNote: "หน้าจอจริงของระบบ ทำงานในเบราว์เซอร์ของคุณด้วยข้อมูลตัวอย่างจากแล็บ",
  workflowSource: "ดู Source Code",
  logTitle: "คำสั่งอ่านล่าสุด",
  archLabel: "สถาปัตยกรรม",
  archNote: "Snapshot และผลรีวิวเก็บไว้ในเครื่องเป็นไฟล์ JSON ไม่มีอะไรเขียนกลับไปที่ Check Point",
  labLabel: "แล็บ ClusterXL ที่ใช้ทดสอบ",
  labNote: "แผนผังแบบย่อ ไม่ใช่การเดินสายทั้งหมด · Management HA และ NAT อยู่ในแล็บเดียวกัน",
  workflowNote: "Insight for humans.<br>Decisions by humans.",
  quoteCaption: "หลักการออกแบบของ Firewall Insight",
  sourceKicker: "GO DEEPER",
  sourceTitle: "อยากรู้ว่าเบื้องหลัง<br><em>ทำงานอย่างไร?</em>",
  sourceDescription: "เปิดดู Source Code, สถาปัตยกรรม, วิธีติดตั้ง และรายละเอียดฟีเจอร์ทั้งหมดบน GitHub แล้วลองสำรวจแนวคิดของ Firewall Insight ต่อได้เลย",
  sourceButton: "เปิดโปรเจกต์บน GitHub",
  ctaResearch: "ดูผลการทดลอง",
  qrCaption: "สแกนเพื่อดู Source Code",
  footerNote: "อ่านเพื่อเข้าใจ • วิเคราะห์เพื่อทบทวน • คนเป็นผู้ตัดสินใจ",
  footProduct: "ผลิตภัณฑ์",
  footResources: "เอกสาร",
  footSafety: "โมเดลความปลอดภัย",
  footSetup: "วิธีติดตั้ง",
  footLimits: "ข้อจำกัดที่รู้อยู่",
  footResearch: "งานวิจัย",
  footPaper: "ผลการทดลอง",
  backTop: "กลับขึ้นด้านบน ↑",
  zoomHint: "แตะเพื่อขยาย",
  lightboxHint: "ปัดซ้าย–ขวาเพื่อดูทั้งหน้าจอ",
  shareBtn: "แชร์",
  copyrightNote: "Independent project · Check Point is a trademark of its respective owner."
};

const featureData = {
  analysis: {
    image: 'assets/analyze.jpg', path: 'ANALYZE',
    th: {overline: '01 / ANALYZE', title: 'เจาะลึก Rule ที่ควรตรวจทาน', description: 'ตรวจหากฎที่ซ้ำ ซ้อนทับ หรือกว้างเกินไป พร้อมแยกการวิเคราะห์ตาม Layer เพื่อให้เห็นบริบทของผลลัพธ์', facts: ['SHADOWED RULES', 'DUPLICATES', 'INLINE LAYERS'], alt: 'หน้าจอ Analyze แสดงผลวิเคราะห์ Policy', caption: 'ภาพหน้าจอจริง / 15 ต.ค. 2026'},
    en: {overline: '01 / ANALYZE', title: 'Find the rules worth reviewing', description: 'Inspect duplicate, shadowed, and overly broad rules. Analysis stays within each layer so findings keep their policy context.', facts: ['SHADOWED RULES', 'DUPLICATES', 'INLINE LAYERS'], alt: 'Policy analysis screen in Firewall Insight', caption: 'ACTUAL PRODUCT SCREENSHOT / 15 OCT 2026'}
  },
  path: {
    image: 'assets/traffic-path.png', path: 'TRAFFIC PATH',
    th: {overline: '02 / TRAFFIC PATH', title: 'ตามเส้นทางของทราฟฟิก', description: 'ระบุต้นทาง ปลายทาง และบริการ เพื่อจำลองการจับคู่ Rule ตามการตั้งค่า พร้อมระดับความมั่นใจของผลลัพธ์', facts: ['SOURCE → DESTINATION', 'RULE MATCH', 'CONFIDENCE'], alt: 'ผล Traffic Path จากวิดีโอตัวอย่างที่ผู้ใช้จัดเตรียม', caption: 'ภาพจากวิดีโอตัวอย่างที่ผู้ใช้จัดเตรียม / 15 ต.ค. 2026'},
    en: {overline: '02 / TRAFFIC PATH', title: 'Follow the traffic path', description: 'Enter source, destination, and service to simulate a rule match from configuration, with a confidence level for the result.', facts: ['SOURCE → DESTINATION', 'RULE MATCH', 'CONFIDENCE'], alt: 'Traffic Path result from a user-provided demo recording', caption: 'FRAME FROM USER-PROVIDED DEMO / 15 OCT 2026'}
  },
  map: {
    image: 'assets/network-mapping.jpg', path: 'NETWORK MAPPING',
    th: {overline: '03 / NETWORK MAPPING', title: 'เห็นโครงข่ายในภาพเดียว', description: 'ดู Gateway, Interface และ Subnet เป็นแผนที่ที่สำรวจได้ พร้อมข้อมูล Routing จาก Gaia API เมื่อมีการเปิดใช้', facts: ['GATEWAYS', 'INTERFACES', 'SUBNETS'], alt: 'หน้าจอ Network Mapping ของ Firewall Insight', caption: 'ภาพหน้าจอจริง / 15 ต.ค. 2026'},
    en: {overline: '03 / NETWORK MAPPING', title: 'See the network in context', description: 'Explore gateways, interfaces, and subnets as a map, with Gaia routing overlaid when that optional integration is enabled.', facts: ['GATEWAYS', 'INTERFACES', 'SUBNETS'], alt: 'Firewall Insight network mapping screen', caption: 'ACTUAL PRODUCT SCREENSHOT / 15 OCT 2026'}
  },
  diff: {
    image: 'assets/policy-diff.jpg', path: 'POLICY DIFF',
    th: {overline: '04 / POLICY DIFF', title: 'รู้ว่าอะไรเปลี่ยนไป', description: 'เปรียบเทียบ Snapshot สองชุดเพื่อเห็น Rule ที่เพิ่ม ลบ แก้ไข ย้าย หรือมีขอบเขตเปลี่ยนไป โดยแยกกรณีที่เปรียบเทียบไม่ได้ออกชัดเจน', facts: ['SNAPSHOT A / B', 'SCOPE CHANGES', 'UNVERIFIABLE'], alt: 'หน้าจอ Policy Diff เปรียบเทียบ Snapshot', caption: 'ภาพหน้าจอจริง / 15 ต.ค. 2026'},
    en: {overline: '04 / POLICY DIFF', title: 'Know what changed', description: 'Compare two snapshots to see added, removed, modified, moved, and scope-changed rules, with incomparable reach shown separately.', facts: ['SNAPSHOT A / B', 'SCOPE CHANGES', 'UNVERIFIABLE'], alt: 'Policy Diff snapshot comparison screen', caption: 'ACTUAL PRODUCT SCREENSHOT / 15 OCT 2026'}
  },
  compliance: {
    image: 'assets/compliance.jpg', path: 'COMPLIANCE',
    th: {overline: '05 / COMPLIANCE', title: 'ตรวจตามเกณฑ์ที่ทีมเลือก', description: 'ใช้ Profile ของทีมตรวจ Policy และดูเหตุผลของแต่ละข้อ แยกผลที่ตรวจไม่ได้อย่างชัดเจน ไม่ตีความว่าเป็นผลผ่าน', facts: ['CUSTOM PROFILES', 'TRACEABLE CHECKS', 'NO FALSE PASS'], alt: 'หน้าจอ Compliance แสดงผลการตรวจ', caption: 'ภาพหน้าจอจริง / 15 ต.ค. 2026'},
    en: {overline: '05 / COMPLIANCE', title: 'Check against your criteria', description: 'Run a chosen profile and inspect each check. Unverifiable results stay visible rather than being counted as a pass.', facts: ['CUSTOM PROFILES', 'TRACEABLE CHECKS', 'NO FALSE PASS'], alt: 'Firewall Insight compliance results screen', caption: 'ACTUAL PRODUCT SCREENSHOT / 15 OCT 2026'}
  },
  health: {
    image: 'assets/gateway-health.jpg', path: 'GATEWAY HEALTH',
    th: {overline: '06 / GATEWAY HEALTH', title: 'อ่านสถานะเกตเวย์ ณ ขณะหนึ่ง', description: 'สถานะ Interface บทบาทในคลัสเตอร์ และเวอร์ชันซอฟต์แวร์ ผ่าน Gaia API ที่บังคับ allowlist ตอนเรียกใช้ เกตเวย์ที่ไม่ตอบถูกรายงานเป็นปัญหาระดับสูง ไม่ใช่ผลว่าง', facts: ['GAIA API', 'CLUSTER ROLES', 'BASELINES'], alt: 'หน้าจอ Gateway Health ของ Firewall Insight', caption: 'ภาพหน้าจอจริง / 15 ต.ค. 2026'},
    en: {overline: '06 / GATEWAY HEALTH', title: 'Read gateway state at one instant', description: 'Interface state, cluster roles and software build over the Gaia API, with a read allowlist enforced at call time. A gateway that doesn’t answer is a high-severity finding, not an empty result.', facts: ['GAIA API', 'CLUSTER ROLES', 'BASELINES'], alt: 'Firewall Insight gateway health screen', caption: 'ACTUAL PRODUCT SCREENSHOT / 15 OCT 2026'}
  },
  usage: {
    image: 'assets/rule-usage.jpg', path: 'RULE USAGE',
    th: {overline: '07 / RULE USAGE', title: 'ดูว่ากฎไหนมีทราฟฟิกจริง', description: 'นับ Log ของไฟร์วอลล์ต่อกฎข้าง Hit counter แต่ละกฎได้คำตัดสินเดียว เช่น seen, no traffic, not in sample หรือ not logged เพราะ Log เป็นตัวอย่าง ไม่ใช่การนับทั้งหมด', facts: ['LOG SAMPLE', 'PER-RULE VERDICT', 'NOT IN SAMPLE ≠ UNUSED'], alt: 'หน้าจอ Rule Usage ของ Firewall Insight', caption: 'ภาพหน้าจอจริง / 15 ต.ค. 2026'},
    en: {overline: '07 / RULE USAGE', title: 'See which rules carry traffic', description: 'Firewall log records counted per rule beside the hit counter. Each rule gets one verdict — seen, no traffic, not in sample, not logged — because logs are a sample, not a count.', facts: ['LOG SAMPLE', 'PER-RULE VERDICT', 'NOT IN SAMPLE ≠ UNUSED'], alt: 'Firewall Insight rule usage screen', caption: 'ACTUAL PRODUCT SCREENSHOT / 15 OCT 2026'}
  },
  trends: {
    image: 'assets/trends.jpg', path: 'TRENDS',
    th: {overline: '08 / TRENDS', title: 'ดูแนวโน้มจากข้อมูลที่เก็บจริง', description: 'กราฟ Optimization score, Compliance failures, การเปลี่ยนแปลงกฎ และกฎที่ไม่มี hit วาดจากรีวิวและ Snapshot ที่เก็บจริงเท่านั้น จุดที่ขาดทำให้เส้นขาด ไม่ถูกวาดเป็นศูนย์', facts: ['REAL READINGS ONLY', 'TIME TO SCALE', 'GAPS STAY GAPS'], alt: 'หน้าจอ Trends ของ Firewall Insight', caption: 'ภาพหน้าจอจริง / 15 ต.ค. 2026'},
    en: {overline: '08 / TRENDS', title: 'Trends from readings you took', description: 'Optimization score, compliance failures, rule changes and zero-hit rules drawn only from reviews and snapshots that were taken. A missing reading breaks the line instead of drawing zero.', facts: ['REAL READINGS ONLY', 'TIME TO SCALE', 'GAPS STAY GAPS'], alt: 'Firewall Insight trends screen', caption: 'ACTUAL PRODUCT SCREENSHOT / 15 OCT 2026'}
  }
};

// Strings used by the interactive demos. Demo data is illustrative and labelled as sample data on the page.
const ui = {
  th: {
    copy: 'คัดลอก', copied: 'คัดลอกแล้ว', copyStatus: 'คัดลอกคำสั่ง git clone แล้ว',
    linkCopied: 'คัดลอกลิงก์แล้ว', expand: 'ขยายภาพหน้าจอ', close: 'ปิด', toTop: 'กลับขึ้นด้านบน',
    allowed: 'อยู่ใน READ_COMMANDS', blocked: 'ไม่มีเส้นทางโค้ด — เทสต์ล้มทันที',
    states: { exact: 'ทุกเงื่อนไขประเมินได้ — ยืนยันผล', inferred: 'อนุมานจากข้อมูลที่มี — ควรตรวจเพิ่ม', unknown: 'มีเงื่อนไขที่แบบจำลองไม่รองรับ เช่น DCE-RPC, Time หรือ Content — งดตอบ' },
    askQuestion: 'ทำไม 192.0.2.10 เข้า 198.51.100.5 ด้วย rdp ไม่ได้', askChips: [['Source', '192.0.2.10'], ['Destination', '198.51.100.5'], ['Service', 'rdp']], askTrace: 'ส่งเข้า Trace เดียวกับฟอร์ม',
    gwSimulate: 'จำลองเกตเวย์ไม่ตอบ', gwRestore: 'คืนค่า', gwNotRead: 'NOT READ · high severity', gwNormal: '2 findings · 1 high',
    diffInsert: 'แทรกกฎใหม่ที่ลำดับ 2', diffUndo: 'ย้อนกลับ',
    diffSummaryIdle: 'Snapshot ตรงกันทุกกฎ', diffSummary: '+1 เพิ่ม · 3 ย้ายตำแหน่ง · 0 ถูกแก้ไข', diffNaive: 'ถ้าจับคู่ด้วยเลขลำดับ: ดูเหมือน 4 กฎถูกแก้ไข',
    moved: 'ย้าย', added: 'ใหม่',
    feed: [
      ['Shadowed', 'Rule 7 ถูกบดบังโดย Rule 3', 'warn'],
      ['Duplicate', 'Rule 12 ซ้ำกับ Rule 14', 'warn'],
      ['Any/Any/Any', 'Rule 9 เปิดกว้างเกินไป', 'bad'],
      ['Unused', 'Rule 15 ไม่มี hit — ทบทวน ไม่ใช่ลบ', 'muted'],
      ['Unknown', 'Rule 4 (DCE-RPC) ประเมินไม่ได้ — งดตอบ', 'unknown'],
      ['Not read', 'Gateway health อ่านไม่ได้ ≠ ไม่มีปัญหา', 'unknown'],
      ['Exact', '192.168.10.5 → Rule 11.1 Accept', 'ok']
    ]
  },
  en: {
    copy: 'Copy', copied: 'Copied', copyStatus: 'git clone command copied',
    linkCopied: 'Link copied', expand: 'Expand screenshot', close: 'Close', toTop: 'Back to top',
    allowed: 'In READ_COMMANDS', blocked: 'No code path — the test fails',
    states: { exact: 'Every condition evaluated — confirmed', inferred: 'Derived from partial data — check further', unknown: 'A condition the model can’t evaluate, e.g. DCE-RPC, Time or Content — abstain' },
    askQuestion: 'can 192.0.2.10 reach 198.51.100.5 on https?', askChips: [['Source', '192.0.2.10'], ['Destination', '198.51.100.5'], ['Service', 'https']], askTrace: 'Runs the same trace as the form',
    gwSimulate: 'Simulate an unreachable gateway', gwRestore: 'Restore', gwNotRead: 'NOT READ · high severity', gwNormal: '2 findings · 1 high',
    diffInsert: 'Insert a rule at position 2', diffUndo: 'Undo',
    diffSummaryIdle: 'Snapshots match rule for rule', diffSummary: '+1 added · 3 moved · 0 rewritten', diffNaive: 'Matched by number: 4 rules would look rewritten',
    moved: 'moved', added: 'new',
    feed: [
      ['Shadowed', 'Rule 7 shadowed by Rule 3', 'warn'],
      ['Duplicate', 'Rule 12 duplicates Rule 14', 'warn'],
      ['Any/Any/Any', 'Rule 9 is overly broad', 'bad'],
      ['Unused', 'Rule 15 has no hits — review, not delete', 'muted'],
      ['Unknown', 'Rule 4 (DCE-RPC) can’t be evaluated — abstain', 'unknown'],
      ['Not read', 'Gateway health unreadable ≠ healthy', 'unknown'],
      ['Exact', '192.168.10.5 → Rule 11.1 Accept', 'ok']
    ]
  }
};

// Commands for the read-only guard demo. Allowed entries come from the README's READ_COMMANDS list.
const guardCommands = [
  ['show-access-rulebase', true], ['set-access-rule', false], ['where-used', true], ['publish', false],
  ['show-gateways-and-servers', true], ['install-policy', false], ['show-logs', true], ['delete-host', false]
];

// Code samples transcribed from the project README.
const codeSamples = {
  mgmt: [
    '# Management API — the only commands issued',
    'login  logout  show-packages  show-package',
    'show-access-layers  show-access-rulebase',
    'show-nat-rulebase  show-object',
    'show-gateways-and-servers  show-unused-objects',
    'show-hosts  show-networks  show-address-ranges',
    'show-groups  where-used  show-logs',
    '',
    '# no add-* / set-* / delete-* / publish / install-policy',
    '# tests/test_v413_structure.py fails if one appears'
  ],
  gaia: [
    '# app/gaia.py — allowlist enforced at call time',
    'show-routes  show-static-routes  show-interfaces',
    'show-interface  show-bond-interfaces',
    'show-cluster-state  show-version  show-asset',
    'show-lldp-status  show-physical-interfaces-xcvr',
    '',
    'GAIA_ENABLED=false   # off unless configured'
  ],
  setup: [
    'python -m venv .venv',
    '.\\.venv\\Scripts\\Activate.ps1',
    'pip install -r requirements.txt',
    'copy .env.example .env   # add Management details',
    'pytest -q                # no Management Server needed',
    'uvicorn app.main:app --host 0.0.0.0 --port 8000'
  ],
  docker: [
    'docker compose up --build   # reads .env via env_file',
    '',
    '# GET /health',
    '{"status": "ok", "mode": "read-only", ...}',
    '',
    '# GET /api/checkpoint/test (signed in)',
    '{"connected": true, "read_only": true, ...}'
  ]
};

const readCommands = ['show-packages', 'show-access-layers', 'show-access-rulebase', 'show-nat-rulebase', 'show-gateways-and-servers', 'show-unused-objects', 'show-groups', 'where-used', 'show-logs', 'show-object'];

// Per 100 questions, single-layer policy (paper v12, E2).
const chartWrong = { 10: 6.9, 20: 12.1, 30: 22.7 };
const chartConfirmed = { 10: 94.5, 20: 90.6, 30: 82.4 };

return { thai, featureData, ui, guardCommands, codeSamples, readCommands, chartWrong, chartConfirmed };
})();

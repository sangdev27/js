
let bank = {
  NB: { MCQ: [], ESSAY: [] },
  TH: { MCQ: [], ESSAY: [] },
  VD: { MCQ: [], ESSAY: [] },
  VDH: { MCQ: [], ESSAY: [] }
};
function isMCQ(content, a='', b='', c='', d='') {
  const raw = (content || '').toString();
  if(/chứng minh|giải thích|trình bày|viết đoạn|phân tích|lập luận|tự luận|chứng tỏ/i.test(raw)) return false;

  const hasOptions = (a && a.trim()) || (b && b.trim()) || (c && c.trim()) || (d && d.trim());
  const hasABCD = /(^|\s)[ABCD][\.|\)]\s+/i.test(raw);
  const hasAnswerLetter = /[Đđ]áp\s*án\s*[:\-]?\s*[ABCD]/i.test(raw) || /Answer\s*[:\-]?\s*[ABCD]/i.test(raw);
  return Boolean(hasOptions || hasABCD || hasAnswerLetter);
}
function extractOptions(content) {
  const optMap = { A: '', B: '', C: '', D: '' };
  const lines = content.split('\n');
  let cleanContent = '';
  let inOptions = false;
  let lastLetter = null;
  for (let rawLine of lines) {
    let line = rawLine.trim();
    if (/\(\s*đáp\s*án\s*.*\)/i.test(rawLine) || 
        /đáp\s*án\s*[:\-]?\s*[ABCD]/i.test(line) || 
        /answer/i.test(line)) {
      continue;
    }
    const optionMatch = rawLine.match(/^\s*([ABCD])[.\)\s]\s*(.*)/i);
    if (optionMatch) {
      inOptions = true;
      const letter = optionMatch[1].toUpperCase();
      const text = optionMatch[2].trim();
      optMap[letter] = text;
      lastLetter = letter;
      continue;
    }
    if (inOptions && line && lastLetter) {
      optMap[lastLetter] += ' ' + line;
      continue;
    }
    if (cleanContent) cleanContent += ' ';
    cleanContent += rawLine.trim();
  }
  return {
    content: cleanContent.trim(),
    a: optMap.A,
    b: optMap.B,
    c: optMap.C,
    d: optMap.D
  };
}
function parseQuestions() {
  const text = document.getElementById('input').value || '';
  if (!text.trim()) return;

  const lines = text.split('\n');
  const entries = [];
  let current = '';
  let isInQuestion = false;
  const startPatterns = [
    /^\s*Câu\s*\d+/i,
    /^\s*Q\d+/i,
    /^\s*\d+[\.)]\s*(NB|TH|VD|VDH|VDC)?/i,
    /^\s*[A-Z0-9_-]+\|/i
  ];
  const optionLinePattern = /^\s*[ABCD][\.\)]/i;
  for (let rawLine of lines) {
    let line = rawLine.trim();

    if (!line) {
      if (isInQuestion && current) {
        current += '\n';
      }
      continue;
    }

    const isNewQuestionStart = startPatterns.some(p => p.test(line));
    const isOptionLine = optionLinePattern.test(line);
    if (isNewQuestionStart && !isOptionLine) {
      if (isInQuestion && current.trim()) {
        entries.push(current.trim());
      }
      current = rawLine; 
      isInQuestion = true;
    } else {
      if (isInQuestion) {
        current += '\n' + rawLine;
      } else {
        current = rawLine;
        isInQuestion = true;
      }
    }
  }
  if (isInQuestion && current.trim()) {
    entries.push(current.trim());
  }

  if(entries.length === 0) {
    const fallback = lines.map(l => l.trim()).filter(l => l);
    if(fallback.length > 0) {
      entries.push(...fallback);
    }
  }

  bank = { NB: {MCQ:[], ESSAY:[]}, TH: {MCQ:[], ESSAY:[]}, VD: {MCQ:[], ESSAY:[]}, VDH: {MCQ:[], ESSAY:[]} };
  let added = 0;

  for (let entry of entries) {
    let code = 'Q' + String(added + 1).padStart(3, '0');
    let level = 'NB';
    let rawContent = entry;
    const levelMatch = entry.match(/(NB|TH|VD|VDH|VDC)/i);
    if (levelMatch) {
      level = levelMatch[1].toUpperCase();
      if(level === 'VDC') level = 'VDH';
    }
    if (!['NB','TH','VD','VDH'].includes(level)) level = 'NB';
    const extracted = extractOptions(entry);
    const q = {
      code,
      level,
      content: extracted.content || entry.replace(/(NB|TH|VD|VDH|VDC).*/i, '').trim(),
      a: extracted.a, b: extracted.b, c: extracted.c, d: extracted.d,
      type: (extracted.a || extracted.b || extracted.c || extracted.d) ? 'MCQ' : 'ESSAY',
      rubric: ''
    };
    if (q.type === 'ESSAY') {
      q.rubric = 'Theo barem chấm của giáo viên';
    }
    bank[level][q.type].push(q);
    added++;
  }
  updateStats();
  window.lastParsedEntries = entries;
  window.lastBank = bank;
  const dbg = document.getElementById('parseDebug');
  if(dbg){
    try{ dbg.textContent = JSON.stringify({entries: entries, bankSummary: {
      NB: {MCQ: bank.NB.MCQ.length, ESSAY: bank.NB.ESSAY.length},
      TH: {MCQ: bank.TH.MCQ.length, ESSAY: bank.TH.ESSAY.length},
      VD: {MCQ: bank.VD.MCQ.length, ESSAY: bank.VD.ESSAY.length},
      VDH: {MCQ: bank.VDH.MCQ.length, ESSAY: bank.VDH.ESSAY.length}
    }}, null, 2);}catch(e){ dbg.textContent = String(entries.slice(0,20)); }
  }
  alert(`Đã thêm ${added} câu vào ngân hàng. Mở Debug Parser để xem kết quả chi tiết.`);
}

function countMCQ() {
  return Object.values(bank).reduce((sum, lev) => sum + lev.MCQ.length, 0);
}
function countEssay() {
  return Object.values(bank).reduce((sum, lev) => sum + lev.ESSAY.length, 0);
}

function updateStats() {
  const s = bank;
  document.getElementById('stats').innerHTML = `
    <strong>Ngân hàng câu hỏi hiện tại:</strong><br>
    NB: ${s.NB.MCQ.length} TN + ${s.NB.ESSAY.length} TL 
    TH: ${s.TH.MCQ.length} TN + ${s.TH.ESSAY.length} TL 
    VD: ${s.VD.MCQ.length} TN + ${s.VD.ESSAY.length} TL 
    VDH: ${s.VDH.MCQ.length} TN + ${s.VDH.ESSAY.length} TL<br>
    <strong>Tổng: ${countMCQ()} trắc nghiệm + ${countEssay()} tự luận = ${countMCQ()+countEssay()} câu</strong>
  `;
}
function shuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}
function generateVersions() {
  const N = parseInt(document.getElementById('numVersions').value) || 1;
  const reqLevel = {
    NB: parseInt(document.getElementById('nb').value) || 0,
    TH: parseInt(document.getElementById('th').value) || 0,
    VD: parseInt(document.getElementById('vd').value) || 0,
    VDH: parseInt(document.getElementById('vdh').value) || 0
  };
  let reqMCQ = parseInt(document.getElementById('numMCQ').value) || 0;
  let reqEssay = parseInt(document.getElementById('numEssay').value) || 0;

  const totalReq = reqLevel.NB + reqLevel.TH + reqLevel.VD + reqLevel.VDH;
  if(totalReq > 0 && totalReq !== (reqMCQ + reqEssay)) {
    if(!confirm(`Tổng mức độ (${totalReq}) ≠ Tổng loại câu (${reqMCQ}+${reqEssay}).\nVẫn tiếp tục?`)) return;
  }
  const versions = [];
  for(let v = 0; v < N; v++) {
    const selected = [];
    let remainingMCQ = reqMCQ;
    let remainingEssay = reqEssay;
    for(let lev of ['NB','TH','VD','VDH']) {
      const need = reqLevel[lev];
      if(need === 0) continue;
      const mcqPool = (bank[lev] && bank[lev].MCQ) ? bank[lev].MCQ.slice() : [];
      const essayPool = (bank[lev] && bank[lev].ESSAY) ? bank[lev].ESSAY.slice() : [];
      const takeMCQ = Math.min(need, remainingMCQ, mcqPool.length);
      const takeEssay = Math.min(need - takeMCQ, remainingEssay, essayPool.length);
      shuffle(mcqPool);
      for(let i = 0; i < takeMCQ; i++) selected.push(mcqPool[i]);
      shuffle(essayPool);
      for(let i = 0; i < takeEssay; i++) selected.push(essayPool[i]);

      remainingMCQ -= takeMCQ;
      remainingEssay -= takeEssay;
    }

    const allMCQ = ['NB','TH','VD','VDH'].flatMap(lev => (bank[lev] && bank[lev].MCQ) ? bank[lev].MCQ.slice() : []);
    const allEssay = ['NB','TH','VD','VDH'].flatMap(lev => (bank[lev] && bank[lev].ESSAY) ? bank[lev].ESSAY.slice() : []);
    shuffle(allMCQ);
    while(remainingMCQ > 0 && allMCQ.length > 0) {
      selected.push(allMCQ[Math.floor(Math.random() * allMCQ.length)]);
      remainingMCQ--;
    }
    shuffle(allEssay);
    while(remainingEssay > 0 && allEssay.length > 0) {
      selected.push(allEssay[Math.floor(Math.random() * allEssay.length)]);
      remainingEssay--;
    }
    versions.push({ code: `MÃ ĐỀ ${String.fromCharCode(65 + v)}`, questions: selected });
  }

  displayVersions(versions);
}
function displayVersions(versions) {
  let html = `
    <div style="text-align:center; margin:30px 0; padding:15px; background:#f0f8ff; border-radius:10px;">
      <button onclick="downloadExam()" style="padding:16px 40px; font-size:1.2em; background:#27ae60; color:white; margin:10px;">
        TẢI ĐỀ (HTML, không đáp án)
      </button>
      <button onclick="printClean()" style="padding:16px 40px; font-size:1.2em; background:#e67e22; margin:10px;">
        IN (không đáp án)
      </button>
    </div><hr>`;

  window.latestExamPerVersion = [];
  versions.forEach((ver, i) => {
    const maDe = String.fromCharCode(65 + i);
    let verHtml = `
    <div class="version-block" id="version-block-${i}">
    <div style="background:white; padding:30px; margin:20px auto; max-width:900px; border:3px double #000; border-radius:10px; box-shadow:0 8px 25px rgba(0,0,0,0.15);">
      
      <div style="text-align:center; border-bottom:4px double #000; padding-bottom:20px; margin-bottom:30px; position:relative;">
        <h1 style="margin:10px; font-size:28px;">TRƯỜNG THPT [TÊN TRƯỜNG]</h1>
        <h2 style="margin:10px; color:#c0392b; font-size:26px;">ĐỀ CHÍNH THỨC</h2>
        <h2 style="margin:15px; font-size:32px; color:#e74c3c;">MÃ ĐỀ: ${maDe.padStart(3, '0')}</h2>
        <p style="font-size:18px;"><strong>Thời gian: 90 phút - Không kể thời gian phát đề</strong></p>
        <!-- Copy button placed to the right side of the header -->
        <div style="text-align:right; margin-top:10px;">
          <button onclick="copyVersion(${i})" style="background:#2980b9;color:#fff;padding:8px 14px;border-radius:6px;border:none;cursor:pointer;">Sao chép nội dung MÃ ${maDe}</button>
        </div>
      </div>

      <table style="width:100%; margin-bottom:30px; font-size:18px;">
        <tr>
          <td style="width:65%;"><strong>Họ và tên: </strong>...................................................................</td>
          <td><strong>Lớp: </strong>..............</td>
        </tr>
        <tr>
          <td><strong>Số báo danh: </strong>.................................</td>
          <td><strong>Phòng thi: </strong>..............</td>
        </tr>
      </table>

      <div style="font-size:18px; line-height:1.8;">`;

    // Render questions into the version-specific HTML (verHtml) for this version
    ver.questions.forEach((q, idx) => {
      const stt = idx + 1;
      const badge = q.type === 'MCQ'
        ? '<span class="q-badge mcq"></span>'
        : '<span class="q-badge essay"></span>';

      if (q.type === 'MCQ') {
        verHtml += `
        <div style="margin:30px 0;">
          <strong>Câu ${stt} [${q.level}]:</strong> ${q.content} ${badge}<br><br>
          ${q.a ? '<div style="margin:8px 0;">A. '+q.a+'</div>' : ''}
          ${q.b ? '<div style="margin:8px 0;">B. '+q.b+'</div>' : ''}
          ${q.c ? '<div style="margin:8px 0;">C. '+q.c+'</div>' : ''}
          ${q.d ? '<div style="margin:8px 0;">D. '+q.d+'</div>' : ''}
        </div>`;
      } else {
        verHtml += `
        <div style="margin:40px 0;">
          <strong>Câu ${stt} [${q.level}]</strong> ${badge}: ${q.content}<br><br>
          <div style="border-bottom:2px solid #000; min-height:140px; margin:15px 0;"></div>
          <div style="border-bottom:2px solid #000; min-height:140px; margin:15px 0;"></div>
        </div>`;
      }
    });

    verHtml += `</div></div></div><div style="page-break-before:always;"></div>`;
    try{
      // keep previous behaviour: store HTML for downloads
      window.latestExamPerVersion = window.latestExamPerVersion || [];
      window.latestExamPerVersion[i] = verHtml;
    } catch(e) { window.latestExamPerVersion[i] = String(verHtml); }

    html += verHtml;
  });

  // Lưu HTML của đề (kèm style) để phục vụ chức năng tải file
  try {
    const styles = Array.from(document.head.querySelectorAll('style, link')).map(n => n.outerHTML).join('\n');
    // Remove the control button block (the top center div + hr) from exported HTML so the exported file is standalone
    const cleanedBody = html.replace(/<div[^>]*text-align:center[\s\S]*?<hr\s*\/?>/i, '');
    window.latestExamHTML = `<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>Đề thi</title>${styles}</head><body>${cleanedBody}</body></html>`;
  } catch(e) {
    const cleanedBody = html.replace(/<div[^>]*text-align:center[\s\S]*?<hr\s*\/?>/i, '');
    window.latestExamHTML = `<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>Đề thi</title></head><body>${cleanedBody}</body></html>`;
  }

  document.getElementById('result').innerHTML = html;
}
// Hàm in sạch - chỉ đề, không đáp án, không nút
function printClean() {
  // Ẩn các nút rồi in (trang in sẽ không có đáp án vì đáp án đã bị loại bỏ)
  document.querySelectorAll('button').forEach(btn => btn.style.display = 'none');
  window.print();
  setTimeout(() => {
    document.querySelectorAll('button').forEach(btn => btn.style.display = 'inline-block');
  }, 500);
}

// Tải file HTML chứa đề (không đáp án)
function downloadExam() {
  if(!window.latestExamHTML) {
    alert('Chưa có đề để tải. Vui lòng tạo đề trước.');
    return;
  }

  try {
    const blob = new Blob([window.latestExamHTML], {type: 'text/html;charset=utf-8'});
    const now = new Date();
    const stamp = now.toISOString().slice(0,19).replace(/[:T]/g,'-');
    const filename = `de-thi-${stamp}.html`;

    // IE / Edge (legacy) fallback
    if(window.navigator && window.navigator.msSaveOrOpenBlob) {
      window.navigator.msSaveOrOpenBlob(blob, filename);
      alert('Đã tải xong (IE/Edge fallback).');
      return;
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    // Some browsers require the link to be in the document
    a.style.display = 'none';
    document.body.appendChild(a);

    // Click and remove
    a.click();
    a.remove();

    // Revoke after a short delay
    setTimeout(() => {
      try { URL.revokeObjectURL(url); } catch(e) {}
    }, 1500);

    // Small UI feedback
    const statusId = 'downloadStatus';
    let status = document.getElementById(statusId);
    if(!status) {
      status = document.createElement('div');
      status.id = statusId;
      status.style.marginTop = '8px';
      status.style.fontSize = '0.95em';
      document.getElementById('result').insertAdjacentElement('afterend', status);
    }
    status.textContent = `Đã bắt đầu tải: ${filename}`;

    // Tạo liên kết tải thủ công (fallback) để người dùng bấm nếu trình duyệt chặn download tự động
    const manualId = 'downloadManualLink';
    let manual = document.getElementById(manualId);
    if(manual) manual.remove();
    manual = document.createElement('div');
    manual.id = manualId;
    manual.style.marginTop = '6px';
    manual.innerHTML = `Nếu trình duyệt chặn tự động, <a href="${url}" target="_blank" rel="noopener">mở đề trong tab mới</a> hoặc <a href="${url}" download="${filename}">tải thủ công</a>.`;
    status.insertAdjacentElement('afterend', manual);

  } catch(err) {
    console.error('downloadExam error', err);
    alert('Quá trình tải thất bại. Mở console để xem chi tiết.');
  }
}

function toggleParseDebug(){
  const el = document.getElementById('parseDebug');
  if(!el) return;
  if(el.style.display === 'none' || !el.style.display){
    el.style.display = 'block';
    document.getElementById('toggleDebugBtn').textContent = 'Ẩn Debug Parser';
  } else {
    el.style.display = 'none';
    document.getElementById('toggleDebugBtn').textContent = 'Hiện / Ẩn Debug Parser';
  }
}

// Sao chép nội dung HTML của một mã đề (copy y chan)
function copyVersion(index) {
  if (!window.latestExamPerVersion || !window.latestExamPerVersion[index]) {
    alert('Không tìm thấy dữ liệu mã đề này!');
    return;
  }

  // Lấy HTML gốc đã được lưu khi generate (có đầy đủ định dạng, table, dòng kẻ, v.v.)
  let htmlContent = window.latestExamPerVersion[index];

  // Tạo một div tạm để render HTML và lấy nội dung đẹp
  const tempDiv = document.createElement('div');
  tempDiv.innerHTML = htmlContent;
  tempDiv.style.position = 'fixed';
  tempDiv.style.left = '-9999px';
  tempDiv.style.width = '900px';  // giống width của đề
  document.body.appendChild(tempDiv);

  const range = document.createRange();
  range.selectNode(tempDiv);
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);

  try {
    const successful = document.execCommand('copy');
    if (successful) {
      alert(`Đã sao chép thành công MÃ ĐỀ ${String.fromCharCode(65 + index)}!\nBây giờ bạn có thể paste (Ctrl+V) trực tiếp vào Word → đẹp như in luôn!`);
    } else {
      throw new Error();
    }
  } catch (err) {
    const plainText = tempDiv.innerText || tempDiv.textContent || '';
    navigator.clipboard?.writeText(plainText).then(() => {
      alert('Copy dạng text thành công (có thể paste vào Word được)');
    }).catch(() => {
      alert('Copy thất bại. Hãy thử bôi đen thủ công.');
    });
  }

  selection.removeAllRanges();
  document.body.removeChild(tempDiv);
}
try {
  // Copy HTML (Word sẽ nhận đẹp lung linh)
  const blob = new Blob([htmlContent], { type: 'text/html' });
  const plainBlob = new Blob([tempDiv.innerText], { type: 'text/plain' });
  const data = [new ClipboardItem({ 'text/html': blob, 'text/plain': plainBlob })];

  navigator.clipboard.write(data).then(() => {
    alert(`ĐÃ COPY SIÊU ĐẸP MÃ ĐỀ ${String.fromCharCode(65 + index)}!\nPaste vào Word → đẹp y như file HTML luôn!`);
  });
} catch (err) {
  // Fallback cũ
  document.execCommand('copy');
  alert('Copy thành công (dạng cũ)');
}


function fallbackCopyText(txt){
  const ta = document.createElement('textarea');
  ta.value = txt;
  ta.style.position = 'fixed'; ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();
  try{
    document.execCommand('copy');
    alert('Đã copy nội dung mã đề.');
  }catch(e){
    alert('Copy không thành công. Bạn có thể mở đề trong tab và lưu thủ công.');
  }
  ta.remove();
}

import { session_set, session_get, session_check } from './session.js';
import { encrypt_text, decrypt_text } from './crypto.js';
import { generateJWT, checkAuth } from './jwt_token.js';

function init(){ // 로그인 폼에 쿠키에서 가져온 아이디 입력
        const emailInput = document.getElementById('typeEmailX');
        const idsave_check = document.getElementById('idSaveCheck');
        let get_id = getCookie("id");

        if(get_id) {
        emailInput.value = get_id;
        idsave_check.checked = true;
        }
        session_check();
}
        
document.addEventListener('DOMContentLoaded', () => {
        init();
});

const check_xss = (input) => {
        // DOMPurify 라이브러리 로드 (CDN 사용)
        const DOMPurify = window.DOMPurify;
        // 입력 값을 DOMPurify로 sanitize
        const sanitizedInput = DOMPurify.sanitize(input);
        // Sanitized된 값과 원본 입력 값 비교
        if (sanitizedInput !== input) {
        // XSS 공격 가능성 발견 시 에러 처리
                alert('XSS 공격 가능성이 있는 입력값을 발견했습니다.');
                return false;
        }
        // Sanitized된 값 반환
        return sanitizedInput;
};
  
function setCookie(name, value, expiredays) {
        var date = new Date();
        date.setDate(date.getDate() + expiredays);
        document.cookie = escape(name) + "=" + escape(value) + "; expires=" + date.toUTCString() + ";path=/" + ";SameSite=None; Secure";
}

function getCookie(name) {
        var cookie = document.cookie;
        console.log("쿠키를 요청합니다.");
        if (cookie != "") {
                var cookie_array = cookie.split("; ");
                for ( var index in cookie_array) {
                        var cookie_name = cookie_array[index].split("=");

                        if (cookie_name[0] == "id") {
                                return cookie_name[1];
                        }
                }
        }
        return ;
}

function login_failed() {
  let failCount = parseInt(getCookie('login_fail_count')) || 0;
  failCount += 1;
  setCookie('login_fail_count', failCount);

  let isLocked = failCount >= 3;
  setCookie('login_locked', isLocked ? '1' : '0');

  updateLoginStatus();
}

// 로그인 제한 및 실패 횟수 표시
function updateLoginStatus() {
  const failCount = parseInt(getCookie('login_fail_count')) || 0;
  const isLocked = getCookie('login_locked') === '1';

  document.getElementById('failCount').innerText = `실패 횟수: ${failCount}`;
  document.getElementById('lockStatus').innerText = isLocked
    ? '로그인 제한 상태입니다.'
    : '로그인 가능';

  // 로그인 제한 시 입력/버튼 비활성화
  document.getElementById('loginBtn').disabled = isLocked;
}

function tryLogin() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  // 실제 인증 로직 대신 예시로 'user'/'pass'만 성공 처리
  if (username === 'user' && password === 'pass') {
    alert('로그인 성공');
    setCookie('login_fail_count', 0); // 성공 시 실패횟수 초기화
    setCookie('login_locked', '0');
    updateLoginStatus();
  } else {
    login_failed();
    alert('로그인 실패');
  }
}


function session_del() {//세션 삭제
        if (sessionStorage) {
                sessionStorage.removeItem("Session_Storage_test");
                alert('로그아웃 버튼 클릭 확인 : 세션 스토리지를 삭제합니다.');
        } else {
                alert("세션 스토리지 지원 x");
        }
}

function logout(){
        session_del(); // 세션 삭제
         location.href='../index.html';
}

function session_get() { //세션 읽기
        if (sessionStorage) {
                return sessionStorage.getItem("Session_Storage_pass");
        } else {
                alert("세션 스토리지 지원 x");
        }
}
        
function session_check() { //세션 검사
        if (sessionStorage.getItem("Session_Storage_id")) {
                alert("이미 로그인 되었습니다.");
                location.href='../login/index_login.html'; // 로그인된 페이지로 이동
        }
}
                
/*
function session_set() { //세션 저장
        let session_id = document.querySelector("#typeEmailX"); // DOM 트리에서 ID 검색
        let session_pass = document.querySelector("#typePasswordX"); // DOM 트리에서 pass 검색
        if (sessionStorage) {
                let en_text = encrypt_text(session_pass.value);
                sessionStorage.setItem("Session_Storage_id", session_id.value);
                sessionStorage.setItem("Session_Storage_pass", en_text);
        } else {
                alert("로컬 스토리지 지원 x");
        }
}
*/

function session_set() { //세션 저장
        let session_id = document.querySelector("#typeEmailX"); // DOM 트리에서 ID 검색
        let session_pass = document.querySelector("#typePasswordX"); // DOM 트리에서 pass 검색
        if (sessionStorage) {
                let en_text = encrypt_text(session_pass.value);
                sessionStorage.setItem("Session_Storage_id", session_id.value);
                sessionStorage.setItem("Session_Storage_pass", en_text);
        } else {
                alert("로컬 스토리지 지원 x");
        }
}

function init_logined(){
        if(sessionStorage){
                decrypt_text(); // 복호화 함수
        }

        else{
                alert("세션 스토리지 지원 x");
        }
}
        
        

/*
function login_failed()[
        if (passwordValue == passwordInput) {
                alert('로그인 완료')
        } else {
                alert('로그인 가능 횟수를 초과했습니다. 4분 간 로그인 할 수 없습니다.')
                lockTime = Date.now() + 4 * 60 * 1000;
        }
]
*/
        
const check_input = () => {
        // 전역 변수 추가, 맨 위 위치
        const idsave_check = document.getElementById('idSaveCheck');

        const loginForm = document.getElementById('login_form');
        const loginBtn = document.getElementById('login_btn');
        const emailInput = document.getElementById('typeEmailX');
        const passwordInput = document.getElementById('typePasswordX');

        const c = '아이디, 패스워드를 체크합니다';
            alert(c);

        const emailValue = emailInput.value.trim();
        const passwordValue = passwordInput.value.trim();
        const sanitizedPassword = check_xss(passwordValue);
        // check_xss 함수로 비밀번호 Sanitize
        const sanitizedEmail = check_xss(emailValue);
        // check_xss 함수로 비밀번호 Sanitize

        const payload = {
                id: emailValue,
                exp: Math.floor(Date.now() / 1000) + 3600 // 1시간 (3600초)
        };
        const jwtToken = generateJWT(payload);
        
        if (emailValue === '') {
                alert('이메일을 입력하세요.');
                return false;
        }

        if (passwordValue === '') {
                alert('비밀번호를 입력하세요.');
                return false;
        }
        if (emailValue.length < 5) {
                alert('아이디는 최소 5글자 이상 입력해야 합니다.');
                return false;
        }
        if (passwordValue.length < 12) {
                alert('비밀번호는 반드시 12글자 이상 입력해야 합니다.');
                return false;
        }
        const hasSpecialChar = passwordValue.match(/[!,@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/) !== null;
        if (!hasSpecialChar) {
                alert('패스워드는 특수문자를 1개 이상 포함해야 합니다.');
                return false;
        }
        const hasUpperCase = passwordValue.match(/[A-Z]+/) !== null;
        const hasLowerCase = passwordValue.match(/[a-z]+/) !== null;
        if (!hasUpperCase || !hasLowerCase) {
                alert('패스워드는 대소문자를 1개 이상 포함해야 합니다.');
                return false;
        }

        if (!sanitizedEmail) {
        // Sanitize된 비밀번호 사용
                return false;
        }
        if (!sanitizedPassword) {
        // Sanitize된 비밀번호 사용
                return false;
        }
        // 검사 마무리 단계 쿠키 저장, 최하단 submit 이전
        if(idsave_check.checked == true) { // 아이디 체크 o
                alert("쿠키를 저장합니다.", emailValue);
                setCookie("id", emailValue, 1); // 1일 저장
                alert("쿠키 값 :" + emailValue);
        }
        else{ // 아이디 체크 x
                setCookie("id", emailValue.value, 0); //날짜를 0 - 쿠키 삭제
        }


        console.log('이메일:', emailValue);
        console.log('비밀번호:', passwordValue);
        session_set(); // 세션 생성
        localStorage.setItem('jwt_token', jwtToken);
        loginForm.submit();
        
};
document.getElementById("login_btn").addEventListener('click', check_input);
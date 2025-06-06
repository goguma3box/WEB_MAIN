// 외부 모듈 import
import { session_set, session_get, session_check } from './session.js';
import { encrypt_text, decrypt_text } from './crypto.js';
import { generateJWT, checkAuth } from './jwt_token.js';

// ========================
// 페이지 초기화
// ========================
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    init_logined();
    
    // 암호화된 회원가입 정보 표시 (추가된 기능)
    displayUserInfo();
    
    // 로그아웃 버튼 이벤트 설정
    setupLogoutButton();
});

// ========================
// 기존 함수들 (유지)
// ========================

// XSS 체크 함수
const check_xss = (input) => {
    const DOMPurify = window.DOMPurify;
    const sanitizedInput = DOMPurify.sanitize(input);
    if (sanitizedInput !== input) {
        alert('XSS 공격 가능성이 있는 입력값을 발견했습니다.');
        return false;
    }
    return sanitizedInput;
};

// 쿠키 관련 함수
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
        for (var index in cookie_array) {
            var cookie_name = cookie_array[index].split("=");
            if (cookie_name[0] == "id") {
                return cookie_name[1];
            }
        }
    }
    return;
}

// 기존 세션 삭제 함수
function session_del() {
    if (sessionStorage) {
        sessionStorage.removeItem("Session_Storage_test");
        alert('로그아웃 버튼 클릭 확인 : 세션 스토리지를 삭제합니다.');
    } else {
        alert("세션 스토리지 지원 x");
    }
}

// 쿠키 삭제 헬퍼 함수
function deleteCookie(name) {
    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=' + window.location.hostname + ';';
}

// 기존 세션 관련 함수들
function session_get() {
    if (sessionStorage) {
        return sessionStorage.getItem("Session_Storage_pass");
    } else {
        alert("세션 스토리지 지원 x");
    }
}

function session_check() {
    if (sessionStorage.getItem("Session_Storage_id")) {
        alert("이미 로그인 되었습니다.");
        location.href = '../login/index_login.html';
    }
}

function session_set() {
    let session_id = document.querySelector("#typeEmailX");
    let session_pass = document.querySelector("#typePasswordX");
    if (sessionStorage) {
        let en_text = encrypt_text(session_pass.value);
        sessionStorage.setItem("Session_Storage_id", session_id.value);
        sessionStorage.setItem("Session_Storage_pass", en_text);
    } else {
        alert("로컬 스토리지 지원 x");
    }
}

function init_logined() {
    if (sessionStorage) {
        decrypt_text(); // 기존 복호화 함수
    } else {
        alert("세션 스토리지 지원 x");
    }
}

// ========================
// 새로 추가된 암호화 시스템
// ========================

// 회원가입 정보 암호화용 키 (기존 crypto.js와 다른 용도)
const USER_DATA_ENCRYPTION_KEY = 'userDataKey2024';

// 회원가입 데이터 암호화 함수
function encryptUserData(data) {
    try {
        const jsonString = JSON.stringify(data);
        const encrypted = btoa(jsonString + USER_DATA_ENCRYPTION_KEY);
        return encrypted;
    } catch (error) {
        console.error('회원가입 데이터 암호화 오류:', error);
        return null;
    }
}

// 회원가입 데이터 복호화 함수
function decryptUserData(encryptedData) {
    try {
        const decrypted = atob(encryptedData);
        const jsonString = decrypted.replace(USER_DATA_ENCRYPTION_KEY, '');
        return JSON.parse(jsonString);
    } catch (error) {
        console.error('회원가입 데이터 복호화 오류:', error);
        return null;
    }
}

// 회원가입 함수 - 암호화하여 세션에 저장
function signUp(userData) {
    try {
        console.log('=== 회원가입 시작 ===');
        console.log('원본 데이터:', userData);
        
        // 사용자 데이터 암호화
        const encryptedData = encryptUserData(userData);
        
        if (encryptedData) {
            // 세션에 암호화된 데이터 저장
            sessionStorage.setItem('encryptedUserData', encryptedData);
            console.log('암호화된 회원가입 데이터가 세션에 저장되었습니다.');
            console.log('암호화된 데이터:', encryptedData);
            
            return { success: true, message: '회원가입 완료' };
        } else {
            return { success: false, message: '암호화 실패' };
        }
    } catch (error) {
        console.error('회원가입 오류:', error);
        return { success: false, message: '회원가입 실패' };
    }
}

// 로그인 후 암호화된 회원가입 정보 표시
function displayUserInfo() {
    try {
        console.log('=== 회원가입 정보 확인 시작 ===');
        
        // 세션에서 암호화된 회원가입 데이터 가져오기
        const encryptedData = sessionStorage.getItem('encryptedUserData');
        
        // 세션에 회원가입 정보가 없는 경우
        if (!encryptedData) {
            console.log('세션에 회원가입 정보가 없습니다.');
            console.log('복호화 X, 출력하지 않음');
            return { success: false, message: '회원가입 정보가 없습니다.' };
        }
        
        // 암호화된 데이터 복호화
        console.log('암호화된 회원가입 데이터 발견:', encryptedData);
        const decryptedData = decryptUserData(encryptedData);
        
        if (decryptedData) {
            // 복호화된 회원가입 내용 콘솔에 출력
            console.log('=== 회원가입 정보 복호화 성공 ===');
            console.log('복호화된 회원가입 정보:', decryptedData);
            console.log('사용자명:', decryptedData.username);
            console.log('이메일:', decryptedData.email);
            console.log('가입일:', decryptedData.signupDate);
            
            return { success: true, data: decryptedData, message: '회원가입 정보 로드 성공' };
        } else {
            console.log('회원가입 정보 복호화 실패');
            return { success: false, message: '회원가입 데이터 복호화 실패' };
        }
    } catch (error) {
        console.error('회원가입 정보 로드 오류:', error);
        return { success: false, message: '회원가입 정보 로드 실패' };
    }
}

// 회원가입 세션 확인 함수
function checkUserDataSession() {
    const encryptedData = sessionStorage.getItem('encryptedUserData');
    
    if (encryptedData) {
        console.log('세션에 암호화된 회원가입 데이터가 존재합니다.');
        return true;
    } else {
        console.log('세션에 회원가입 정보가 없습니다.');
        return false;
    }
}

// ========================
// 통합된 로그아웃 함수
// ========================
function logout() {
    try {
        // 1. JWT 토큰 삭제
        localStorage.removeItem('jwt_token');
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        
        // 2. 세션스토리지에서 토큰 삭제
        sessionStorage.removeItem('jwt_token');
        sessionStorage.removeItem('access_token');
        sessionStorage.removeItem('refresh_token');
        
        // 3. 암호화된 회원가입 데이터 삭제 (새로 추가)
        sessionStorage.removeItem('encryptedUserData');
        
        // 4. 쿠키 삭제
        deleteCookie('jwt_token');
        deleteCookie('access_token');
        deleteCookie('refresh_token');
        
        // 5. 기존 세션 삭제 함수 호출
        session_del();
        
        console.log('로그아웃 완료: 모든 토큰, 세션, 회원가입 데이터가 삭제되었습니다.');
        
        // 6. 메인 페이지로 리다이렉트
        location.href = '../index.html';
        
    } catch (error) {
        console.error('로그아웃 중 오류 발생:', error);
        // 에러가 발생해도 기본 로그아웃 동작은 수행
        session_del();
        location.href = '../index.html';
    }
}

// ========================
// 유틸리티 함수들
// ========================

// 특정 토큰만 삭제하는 함수
function removeJWTToken() {
    localStorage.removeItem('jwt_token');
    console.log('JWT 토큰이 삭제되었습니다.');
}

// 모든 사용자 데이터 정리 함수
function clearAllUserData() {
    const keysToRemove = [
        'jwt_token',
        'access_token', 
        'refresh_token',
        'user_info',
        'user_preferences',
        'cart_items'
    ];
    
    keysToRemove.forEach(key => {
        localStorage.removeItem(key);
    });
    
    // 세션스토리지 정리 (암호화된 회원가입 데이터 포함)
    sessionStorage.clear();
    
    console.log('모든 사용자 데이터가 정리되었습니다.');
}

// 토큰 존재 여부 확인 함수
function isTokenExists() {
    const token = localStorage.getItem('jwt_token');
    return token !== null && token !== undefined && token !== '';
}

// 로그인 상태 확인 함수
function checkAuthStatus() {
    if (!isTokenExists()) {
        console.log('토큰이 없습니다. 로그인이 필요합니다.');
        window.location.href = '/login';
        return false;
    }
    return true;
}

// ========================
// 이벤트 설정 함수
// ========================
function setupLogoutButton() {
    const logoutBtn = document.getElementById('logoutBtn');
    
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            if (confirm('정말 로그아웃 하시겠습니까?')) {
                logout();
            }
        });
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
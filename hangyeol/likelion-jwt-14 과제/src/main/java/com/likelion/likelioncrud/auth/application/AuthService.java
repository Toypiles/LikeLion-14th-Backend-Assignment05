package com.likelion.likelioncrud.auth.application;

import com.likelion.likelioncrud.auth.JwtUtil;
import com.likelion.likelioncrud.auth.api.dto.request.LoginRequestDto;
import com.likelion.likelioncrud.auth.api.dto.request.SignupRequestDto;
import com.likelion.likelioncrud.auth.api.dto.request.TokenRefreshRequestDto;
import com.likelion.likelioncrud.auth.api.dto.response.LoginResponseDto;
import com.likelion.likelioncrud.auth.api.dto.response.TokenRefreshResponseDto;
import com.likelion.likelioncrud.auth.domain.RefreshToken;
import com.likelion.likelioncrud.auth.domain.RefreshTokenRepository;
import com.likelion.likelioncrud.common.exception.BusinessException;
import com.likelion.likelioncrud.common.response.code.ErrorCode;
import com.likelion.likelioncrud.member.domain.Member;
import com.likelion.likelioncrud.member.domain.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)  // 기본적으로 읽기 전용 트랜잭션 적용 (조회 성능 최적화)
public class AuthService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;  // SecurityConfig에서 빈으로 등록한 BCryptPasswordEncoder
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    // application.yml의 jwt.refresh-expiration 값 (밀리초)
    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    // 회원가입
    @Transactional  // DB에 저장하는 작업이므로 쓰기 트랜잭션 적용
    public void signup(SignupRequestDto request) {

        // 1. 이메일 중복 체크
        if (memberRepository.existsByEmail(request.email())) {
            throw new BusinessException(ErrorCode.DUPLICATE_EMAIL_EXCEPTION, ErrorCode.DUPLICATE_EMAIL_EXCEPTION.getMessage());
        }

        // 2. 비밀번호 BCrypt 암호화 후 Member 생성
        Member member = Member.builder()
                .name(request.name())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))  // 비밀번호 암호화
                .build();

        // 3. DB 저장
        memberRepository.save(member);
    }


    // 로그인
    @Transactional
    public LoginResponseDto login(LoginRequestDto request) {

        // 1. 이메일로 회원 조회 (없으면 예외 처리)
        // findByEmail()은 Optional<Member>를 반환
        // orElseThrow() -> Optional이 비어있으면 람다식 실행에서 예외 발생
        // 존재하지 않는 이메일로 로그인 시도시 401 UNAUTHORIZED 반환
        Member member = memberRepository.findByEmail(request.email())
                .orElseThrow(() -> new BusinessException(ErrorCode.MEMBER_NOT_FOUND_BY_EMAIL_EXCEPTION, ErrorCode.MEMBER_NOT_FOUND_BY_EMAIL_EXCEPTION.getMessage()));

        // 2. 입력한 비밀번호와 암호화된 비밀번호 비교립
        // passwordEncoder.matches(평문, 암호화된 값)
        // -> 입력한 비밀번호를 BCrypt로 해시해서 DB에 저장된 해시값과 비교
        // -> 일치하면 true, 불일치하면 false
        // !matches() -> 불일치할 떄 예외 발생 -> 400 BAD REQUEST 반환
        if (!passwordEncoder.matches(request.password(), member.getPassword())) {
            throw new BusinessException(ErrorCode.INVALID_PASSWORD_EXCEPTION, ErrorCode.INVALID_PASSWORD_EXCEPTION.getMessage());
        }

        // 3. 인증 성공 → Access Token 발급
        // member.getMemberId()로 userId를 꺼내서 JWT payload의 subject에 저장
        // 짧은 수명 -> 만료되면 Refresh Token으로 재발급
        String accessToken = jwtUtil.generateToken(member.getMemberId());

        // [과제] Refresh Token 발급 및 DB 저장
        // TODO (1): jwtUtil.generateRefreshToken()을 호출해서 refreshToken 문자열을 발급하세요.
        // Refresh Token 발급
        // generateRefreshToen()은 generateToken()과 동일한 구조
        // 차이점 : 만료 시간이 refreshExpiration을 사용해 훨씬 길다.
        // Access Token이 만료됐을 때 이 토큰으로 새 Access Token을 재발급 받을 수 있다.
        String refreshToken = jwtUtil.generateRefreshToken(member.getMemberId());

        // TODO (2): 기존에 저장된 이 사용자의 refresh token을 먼저 삭제하세요.
        //           힌트: refreshTokenRepository.deleteByMemberId(...)
        // 기존의 Refresh Token 삭제
        // 같은 사용자가 재로그인하면 이전 Refresh Token이 DB에 남아 있을 수 있다.
        // -> 중복 저장 방지 -> 이전 토큰 무효화를 위해 먼저 삭제
        // memberId로 해당 사용자의 토큰을 찾아서 삭제
        refreshTokenRepository.deleteByMemberId(member.getMemberId());



        // TODO (3): RefreshToken 엔티티를 빌더로 생성하고 DB에 저장하세요.
        //           만료 시각 계산: LocalDateTime.now().plusSeconds(refreshExpiration / 1000)
        //           힌트: refreshTokenRepository.save(RefreshToken.builder()...build())
        // 새 Refresh Token DB 저장
        // Refresh Token은 Access Token과 달리 DB에 저장해야 함
        // 이유 : 탈취되거나 로그아웃 시 DB에서 삭제해서 무효화할 수 있어야 하기 때문

        // RefreshToken.builder()로 엔티티 생성
        // .memberId() -> 어떤 사용자의 토큰인지 식별
        // .token() -> 실제 JWT Refresh Token 문자열
        // .expiresAt() -> 만료 시각 (LocalDateTime 타입으로 저장)
        // refreshExpiration은 밀리초 단위 -> /1000 해서 초 단위로 변환
        // LocalDateTime.now().plusSeconds() -> 현재 시각에서 초를 더해 만료 시각 계산
        refreshTokenRepository.save(RefreshToken.builder()
                .memberId(member.getMemberId())
                .token(refreshToken)
                .expiredAt(LocalDateTime.now().plusSeconds(refreshExpiration/1000))
                .build());

        // 4. Access Token + Refresh Token 반환
        // 클라이언트는 두 토큰을 저장해두고
        // -> Access Token : 매 API 요청 Header에 사용
        // -> Refresh Token : Access Token 만료시 재발급 요청에 사용
        return new LoginResponseDto(accessToken, refreshToken);
    }

    // [과제] Access Token 재발급
    @Transactional
    public TokenRefreshResponseDto reissue(TokenRefreshRequestDto request) {

        // TODO (1): request에서 refreshToken 문자열을 꺼내세요.
        // 요청에서 refreshToken 문자열 꺼내기
        // TokenRefreshRequestDto는 record 타입
        // -> request.refreshToken()으로 getter 호출
        // 클라이언트가 보낸 Refresh Token 문자열을 변수에 저장
        String refreshToken = request.refreshToken();

        // TODO (2): jwtUtil.validateToken()으로 refresh token의 서명/만료를 검증하세요.
        //           유효하지 않으면 INVALID_REFRESH_TOKEN_EXCEPTION을 throw하세요.
        // Refresh Token 서명/만료 검증
        // jwtUtil.validateToken() -> 내부에서 parseClaims() 호출
        // 만료된 토큰 -> ExpiredJwtException 발생 -> catch -> false 반환
        // 위조, 변조된 토큰 -> SignatureException 발생 -> catch -> false 반환
        // 정상 토큰 -> true 반환
        // !validateToken() -> 유효하지 않으면 예외 발생 -> 400 BAD REQUEST 반환
        if(!jwtUtil.validateToken(refreshToken)){
            throw new BusinessException(
                    ErrorCode.INVALID_REFRESH_TOKEN_EXCEPTION,
                    ErrorCode.INVALID_PASSWORD_EXCEPTION.getMessage());
        }


        // TODO (3): DB에서 refreshToken 문자열로 RefreshToken 엔티티를 조회하세요.
        //           없으면 INVALID_REFRESH_TOKEN_EXCEPTION을 throw하세요.
        //           힌트: refreshTokenRepository.findByToken(refreshToken).orElseThrow(...)
        // DB에서 Refresh Token 조회
        // 서명/만료 검증만으로 부족함
        // 이유 : 서명이 유효해도 로그아웃으로 DB에서 삭제된 토큰 일 수 있음, 또는 탈취된 토큰일 수 있음
        // -> DB에 실제로 존재하는 토큰인지 한번 더 확인
        // findByToken() -> Optional<RefreshToken> 반환
        // orElseThrow() -> DB에 없으면 예외 발생 (이미 로그아웃된 or 탈취된 토큰)
        // savedToken 변수 : 실제로 꺼내 쓰지 않지만, "DB에 존재하는 유효 토큰"임을 확인하는 용도
        RefreshToken savedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new BusinessException(
                        ErrorCode.INVALID_REFRESH_TOKEN_EXCEPTION,
                        ErrorCode.INVALID_REFRESH_TOKEN_EXCEPTION.getMessage()
                ));

        // TODO (4): refresh token에서 userId를 추출하고, 새로운 Access Token을 발급하세요.
        //           힌트: jwtUtil.getUserId(refreshToken), jwtUtil.generateToken(userId)
        // 새 Access Token 발급
        // Refresh Token의 payload에서 userId 추출
        // -> getUserId()가 내부적으로 parseClaims().getSubject()로 꺼낸 후 Long으로 변환
        Long userId = jwtUtil.getUserId(refreshToken);

        // 추출한 userId로 새 Access Token 생성
        // -> Refresh Token은 아직 유효하므로 새로 발급하지 않음
        // -> Access Token만 재발급해서 반환
        String newAccessToken = jwtUtil.generateToken(userId);

        // 5. 새로 발급한 Access Token 반환
        // 클라이언트는 이 토큰으로 기존 만료된 Access Token을 교체해서 사용
        return new TokenRefreshResponseDto(newAccessToken);
    }
}

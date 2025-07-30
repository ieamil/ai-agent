#!/usr/bin/env python3
"""
SonarQube API Entegrasyonu
Gerçek SonarQube verilerini çeker ve analiz eder

Bu modülde olanlar:
- SonarQube REST API'sine bağlanma
- Proje metriklerini çekme (bugs, vulnerabilities, code smells, coverage)
- Issue'ları (sorunları) çekme ve kategorilere ayırma
- Quality Gate durumunu kontrol etme
- Analiz sonuçlarını rapor formatına çevirme

Kullanım örneği:
    analyzer = SonarQubeAnalyzer("https://sonarcloud.io", "YOUR_TOKEN")
    result = analyzer.analyze_project("PROJECT_KEY")
"""

import requests
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class SonarQubeIssue:
    """
    SonarQube issue (sorun) veri yapısı
    
    Attributes:
        key: Issue'nun benzersiz anahtarı
        rule: Kural adı (örn: "java:S1066")
        severity: Önem derecesi (BLOCKER, CRITICAL, MAJOR, MINOR, INFO)
        component: Dosya yolu
        project: Proje anahtarı
        line: Satır numarası
        message: Hata mesajı
        type: Issue tipi (BUG, VULNERABILITY, CODE_SMELL, SECURITY_HOTSPOT)
        created_at: Oluşturulma tarihi
        updated_at: Güncellenme tarihi
    """
    key: str
    rule: str
    severity: str
    component: str
    project: str
    line: int
    message: str
    type: str
    created_at: str
    updated_at: str

@dataclass
class SonarQubeMetric:
    """
    SonarQube metric (ölçüm) veri yapısı
    
    Attributes:
        key: Metric anahtarı (örn: "bugs", "coverage")
        value: Ham değer
        formatted_value: Formatlanmış değer (örn: "78.5%")
    """
    key: str
    value: str
    formatted_value: str

class SonarQubeAPI:
    """
    SonarQube API entegrasyonu
    
    Bu sınıf SonarQube REST API'sine bağlanarak:
    - Proje bilgilerini çeker
    - Metrikleri alır
    - Issue'ları listeler
    - Quality Gate durumunu kontrol eder
    """
    
    def __init__(self, base_url: str, token: Optional[str] = None):
        """
        SonarQube API bağlantısını başlat
        
        Args:
            base_url: SonarQube sunucu URL'si (örn: "https://sonarcloud.io")
            token: API token (opsiyonel, public projeler için gerekli değil)
        """
        # URL'nin sonundaki slash'i kaldır
        self.base_url = base_url.rstrip('/')
        self.token = token
        
        # HTTP session oluştur (performans için)
        self.session = requests.Session()
        
        # Token varsa authentication header'ı ekle
        if token:
            self.session.auth = (token, '')
    
    def get_project_issues(self, project_key: str, branch: str = "main", max_issues: int = None) -> List[SonarQubeIssue]:
        """
        Proje issue'larını (sorunlarını) çek - TÜM ISSUE'LARI ÇEKER!
        
        Args:
            project_key: Proje anahtarı
            branch: Branch adı (varsayılan: "main")
            max_issues: Maksimum çekilecek issue sayısı (None = sınırsız)
            
        Returns:
            Issue listesi (SonarQubeIssue objeleri)
            
        Note:
            Pagination kullanarak TÜM issue'ları çeker. Büyük projeler için zaman alabilir.
        """
        try:
            # SonarQube Issues API endpoint'i
            url = f"{self.base_url}/api/issues/search"
            
            all_issues = []
            page = 1
            page_size = 500  # Her sayfada maksimum 500 issue
            
            print(f"🔄 Issue'lar çekiliyor... (sayfa {page})")
            
            while True:
                # API parametreleri
                params = {
                    'componentKeys': project_key,  # Hangi proje
                    'branch': branch,              # Hangi branch
                    'ps': page_size,               # Sayfa boyutu (page size)
                    'p': page                      # Sayfa numarası (page number)
                }
                
                # API çağrısı yap
                response = self.session.get(url, params=params)
                response.raise_for_status()  # HTTP hatalarını kontrol et
                
                # JSON yanıtını parse et
                data = response.json()
                current_issues = data.get('issues', [])
                
                # Eğer issue yoksa döngüyü bitir
                if not current_issues:
                    break
                
                # Her issue'yu SonarQubeIssue objesine çevir
                for issue_data in current_issues:
                    issue = SonarQubeIssue(
                        key=issue_data.get('key', ''),
                        rule=issue_data.get('rule', ''),
                        severity=issue_data.get('severity', ''),
                        component=issue_data.get('component', ''),
                        project=issue_data.get('project', ''),
                        line=issue_data.get('line', 0),
                        message=issue_data.get('message', ''),
                        type=issue_data.get('type', ''),
                        created_at=issue_data.get('createdAt', ''),
                        updated_at=issue_data.get('updatedAt', '')
                    )
                    all_issues.append(issue)
                
                # Maksimum issue sayısı kontrolü
                if max_issues and len(all_issues) >= max_issues:
                    all_issues = all_issues[:max_issues]
                    print(f"✅ Maksimum issue sayısına ulaşıldı: {max_issues}")
                    break
                
                # Sonraki sayfa
                page += 1
                print(f"🔄 Issue'lar çekiliyor... (sayfa {page}, toplam: {len(all_issues)})")
                
                # Rate limiting için kısa bekleme
                import time
                time.sleep(0.1)
            
            print(f"✅ Toplam {len(all_issues)} issue çekildi!")
            return all_issues
            
        except Exception as e:
            print(f"⚠️  SonarQube issue çekme başarısız: {e}")
            return []
    
    def get_project_metrics(self, project_key: str, branch: str = "main") -> Dict[str, Any]:
        """
        Proje metriklerini çek
        
        Çekilen metrikler:
        - bugs: Hata sayısı
        - vulnerabilities: Güvenlik açığı sayısı
        - code_smells: Kod kokusu sayısı
        - coverage: Test kapsamı yüzdesi
        - duplicated_lines_density: Tekrarlanan satır yüzdesi
        - security_hotspots: Güvenlik noktası sayısı
        
        Args:
            project_key: Proje anahtarı
            branch: Branch adı (varsayılan: "main")
            
        Returns:
            Metrik sözlüğü
        """
        try:
            # SonarQube Measures API endpoint'i
            url = f"{self.base_url}/api/measures/component"
            
            # İstenen metrikler
            params = {
                'component': project_key,
                'branch': branch,
                'metricKeys': 'bugs,vulnerabilities,code_smells,coverage,duplicated_lines_density,security_hotspots'
            }
            
            # API çağrısı yap
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            # JSON yanıtını parse et
            data = response.json()
            metrics = {}
            
            # Her metriği işle
            for measure in data.get('component', {}).get('measures', []):
                metrics[measure['metric']] = {
                    'value': measure.get('value', '0'),
                    'formatted_value': measure.get('formattedValue', '0')
                }
            
            return metrics
            
        except Exception as e:
            print(f"⚠️  SonarQube metric çekme başarısız: {e}")
            return {}
    
    def get_project_info(self, project_key: str) -> Dict[str, Any]:
        """
        Proje bilgilerini çek
        
        Çekilen bilgiler:
        - name: Proje adı
        - key: Proje anahtarı
        - qualifier: Proje tipi (TRK = proje)
        - visibility: Görünürlük (public/private)
        - lastAnalysisDate: Son analiz tarihi
        
        Args:
            project_key: Proje anahtarı
            
        Returns:
            Proje bilgileri sözlüğü
        """
        try:
            # SonarQube Projects API endpoint'i
            url = f"{self.base_url}/api/projects/search"
            params = {
                'projects': project_key
            }
            
            # API çağrısı yap
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            # JSON yanıtını parse et
            data = response.json()
            projects = data.get('components', [])
            
            # İlk projeyi döndür (genellikle tek proje olur)
            if projects:
                return projects[0]
            return {}
            
        except Exception as e:
            print(f"⚠️  SonarQube proje bilgisi çekme başarısız: {e}")
            return {}
    
    def get_quality_gate_status(self, project_key: str, branch: str = "main") -> Dict[str, Any]:
        """
        Quality Gate durumunu çek
        
        Quality Gate, projenin kalite standartlarını karşılayıp karşılamadığını kontrol eder.
        Durumlar: OK, ERROR, WARN
        
        Args:
            project_key: Proje anahtarı
            branch: Branch adı (varsayılan: "main")
            
        Returns:
            Quality Gate durumu sözlüğü
        """
        try:
            # SonarQube Quality Gate API endpoint'i
            url = f"{self.base_url}/api/qualitygates/project_status"
            params = {
                'projectKey': project_key,
                'branch': branch
            }
            
            # API çağrısı yap
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            # JSON yanıtını parse et
            data = response.json()
            return data.get('projectStatus', {})
            
        except Exception as e:
            print(f"⚠️  SonarQube Quality Gate durumu çekme başarısız: {e}")
            return {}

class SonarQubeAnalyzer:
    """
    SonarQube analiz sınıfı
    
    Bu sınıf SonarQubeAPI'yi kullanarak kapsamlı proje analizi yapar:
    - Tüm metrikleri çeker
    - Issue'ları kategorilere ayırır
    - Quality Gate durumunu kontrol eder
    - Sonuçları rapor formatına çevirir
    """
    
    def __init__(self, base_url: str, token: Optional[str] = None):
        """
        Analizörü başlat
        
        Args:
            base_url: SonarQube sunucu URL'si
            token: API token (opsiyonel)
        """
        self.api = SonarQubeAPI(base_url, token)
    
    def analyze_project(self, project_key: str, branch: str = "main", max_issues: int = None) -> Dict[str, Any]:
        """
        Projeyi kapsamlı şekilde analiz et - TÜM ISSUE'LARI ÇEKER!
        
        Bu metod şu adımları takip eder:
        1. Proje bilgilerini çeker
        2. Metrikleri alır
        3. Issue'ları listeler (pagination ile TÜM issue'ları)
        4. Quality Gate durumunu kontrol eder
        5. Sonuçları kategorilere ayırır
        
        Args:
            project_key: Proje anahtarı
            branch: Branch adı (varsayılan: "main")
            max_issues: Maksimum çekilecek issue sayısı (None = sınırsız)
            
        Returns:
            Kapsamlı analiz sonuçları sözlüğü
        """
        print(f"🔍 SonarQube analizi başlatılıyor: {project_key}")
        
        # 1. Proje bilgilerini çek
        project_info = self.api.get_project_info(project_key)
        
        # 2. Metrikleri çek (bugs, vulnerabilities, coverage, vb.)
        metrics = self.api.get_project_metrics(project_key, branch)
        
        # 3. Issue'ları çek (TÜM sorunlar - pagination ile)
        print(f"📊 Issue'lar çekiliyor... (maksimum: {'sınırsız' if max_issues is None else max_issues})")
        issues = self.api.get_project_issues(project_key, branch, max_issues)
        
        # 4. Quality Gate durumunu çek
        quality_gate = self.api.get_quality_gate_status(project_key, branch)
        
        # 5. Issue'ları tiplerine göre kategorilere ayır
        issues_by_type = {
            'BUG': [],           # Hatalar
            'VULNERABILITY': [], # Güvenlik açıkları
            'CODE_SMELL': [],    # Kod kokuları
            'SECURITY_HOTSPOT': [] # Güvenlik noktaları
        }
        
        # Her issue'yu uygun kategoriye ekle
        for issue in issues:
            issue_type = issue.type
            if issue_type in issues_by_type:
                issues_by_type[issue_type].append(issue)
        
        # 6. Sonuçları derle ve döndür
        result = {
            'project_info': project_info,
            'metrics': metrics,
            'issues': {
                'total': len(issues),
                'bugs': len(issues_by_type['BUG']),
                'vulnerabilities': len(issues_by_type['VULNERABILITY']),
                'code_smells': len(issues_by_type['CODE_SMELL']),
                'security_hotspots': len(issues_by_type['SECURITY_HOTSPOT'])
            },
            'issues_by_severity': self._group_issues_by_severity(issues),
            'quality_gate': quality_gate,
            'analysis_date': datetime.now().isoformat()
        }
        
        print(f"✅ SonarQube analizi tamamlandı: {len(issues)} issue")
        return result
    
    def _group_issues_by_severity(self, issues: List[SonarQubeIssue]) -> Dict[str, int]:
        """
        Issue'ları önem derecesine (severity) göre grupla
        
        Severity seviyeleri:
        - BLOCKER: En kritik (0)
        - CRITICAL: Kritik (1)
        - MAJOR: Önemli (2)
        - MINOR: Küçük (3)
        - INFO: Bilgi (4)
        
        Args:
            issues: Issue listesi
            
        Returns:
            Severity bazlı sayım sözlüğü
        """
        severity_counts = {'BLOCKER': 0, 'CRITICAL': 0, 'MAJOR': 0, 'MINOR': 0, 'INFO': 0}
        
        # Her issue'nun severity'sini say
        for issue in issues:
            severity = issue.severity
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return severity_counts
    
    def format_for_report(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analiz sonuçlarını rapor formatına çevir
        
        Bu metod, ham analiz sonuçlarını daha kullanışlı bir formata çevirir.
        Özellikle security_quality_agent.py'de kullanılmak üzere tasarlanmıştır.
        
        Args:
            analysis_result: Ham analiz sonuçları
            
        Returns:
            Formatlanmış rapor verisi
        """
        metrics = analysis_result.get('metrics', {})
        issues = analysis_result.get('issues', {})
        quality_gate = analysis_result.get('quality_gate', {})
        
        # Rapor formatına çevir
        return {
            'sonarqube': {
                'bugs': int(metrics.get('bugs', {}).get('value', 0)),
                'vulnerabilities': int(metrics.get('vulnerabilities', {}).get('value', 0)),
                'code_smells': int(metrics.get('code_smells', {}).get('value', 0)),
                'coverage': float(metrics.get('coverage', {}).get('value', 0)),
                'duplicated_lines': float(metrics.get('duplicated_lines_density', {}).get('value', 0)),
                'security_hotspots': int(metrics.get('security_hotspots', {}).get('value', 0))
            },
            'quality_gate': {
                'status': quality_gate.get('status', 'UNKNOWN'),
                'conditions': quality_gate.get('conditions', [])
            },
            'issues_summary': {
                'total': issues.get('total', 0),
                'bugs': issues.get('bugs', 0),
                'vulnerabilities': issues.get('vulnerabilities', 0),
                'code_smells': issues.get('code_smells', 0),
                'security_hotspots': issues.get('security_hotspots', 0)
            }
        }

# Test fonksiyonu
def test_sonarqube_connection(base_url: str, project_key: str, token: Optional[str] = None, max_issues: int = None):
    """
    SonarQube bağlantısını test et - TÜM ISSUE'LARI ÇEKER!
    
    Bu fonksiyon, SonarQube API'sine bağlanabildiğinizi ve
    proje verilerini çekebildiğinizi test etmek için kullanılır.
    
    Args:
        base_url: SonarQube sunucu URL'si
        project_key: Test edilecek proje anahtarı
        token: API token (opsiyonel)
        max_issues: Maksimum çekilecek issue sayısı (None = sınırsız)
        
    Returns:
        Analiz sonuçları veya None (hata durumunda)
    """
    try:
        # Analizör oluştur
        analyzer = SonarQubeAnalyzer(base_url, token)
        
        # Projeyi analiz et (TÜM issue'ları çek)
        print(f"🚀 Test başlatılıyor... (maksimum issue: {'sınırsız' if max_issues is None else max_issues})")
        result = analyzer.analyze_project(project_key, max_issues=max_issues)
        
        # Sonuçları yazdır
        print("\n📊 SonarQube Analiz Sonuçları:")
        print(f"Proje: {result['project_info'].get('name', 'Bilinmiyor')}")
        print(f"Toplam Issue: {result['issues']['total']}")
        print(f"Bugs: {result['issues']['bugs']}")
        print(f"Vulnerabilities: {result['issues']['vulnerabilities']}")
        print(f"Code Smells: {result['issues']['code_smells']}")
        print(f"Security Hotspots: {result['issues']['security_hotspots']}")
        
        # Severity dağılımını göster
        severity = result['issues_by_severity']
        print(f"\n🔴 Severity Dağılımı:")
        print(f"  BLOCKER: {severity['BLOCKER']}")
        print(f"  CRITICAL: {severity['CRITICAL']}")
        print(f"  MAJOR: {severity['MAJOR']}")
        print(f"  MINOR: {severity['MINOR']}")
        print(f"  INFO: {severity['INFO']}")
        
        return result
        
    except Exception as e:
        print(f"❌ SonarQube bağlantı testi başarısız: {e}")
        return None 
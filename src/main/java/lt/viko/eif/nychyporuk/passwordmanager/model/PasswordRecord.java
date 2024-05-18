package lt.viko.eif.nychyporuk.passwordmanager.model;

public class PasswordRecord {
    private String title;
    private String url;
    private String other;
    private String password;
    private String algorithm;

    public PasswordRecord(String title, String url, String other, String password, String algorithm) {
        this.title = title;
        this.url = url;
        this.other = other;
        this.password = password;
        this.algorithm = algorithm;
    }

    @Override
    public String toString() {
        return "Password Record: \n" +
                "title: " + title + '\n' +
                "url: " + url + '\n' +
                "other: " + other + '\n' +
                "password: " + password + '\n' +
                "algorithm: " + algorithm + '\n';
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getOther() {
        return other;
    }

    public void setOther(String other) {
        this.other = other;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
}

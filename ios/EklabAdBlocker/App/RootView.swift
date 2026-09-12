import SwiftUI

struct RootView: View {
    var body: some View {
        TabView {
            HomeView()
                .tabItem {
                    Label("Home", systemImage: "house.fill")
                }
            ConnectionsView()
                .tabItem {
                    Label("Connections", systemImage: "arrow.up.arrow.down")
                }
            AppsView()
                .tabItem {
                    Label("Apps", systemImage: "square.grid.2x2.fill")
                }
            RulesView()
                .tabItem {
                    Label("Rules", systemImage: "hammer.fill")
                }
        }
    }
}
